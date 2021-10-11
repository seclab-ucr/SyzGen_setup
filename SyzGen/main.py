#! /usr/bin/python3

import argparse
import sys
import logging
import os
import struct
import random
import time
import json

import angr

import syzgen.utils as Utils

from syzgen.analysis.static import findServices, analyze_getTargetAndMethodForIndex, parse_client, \
    analyze_externalMethod, parse_service, find_entitlement
from syzgen.analysis.dynamic import find_client, findAllService, find_default_client
from syzgen.analysis.dispatch import find_dispatchTable
from syzgen.kext.macho import parse_registered_clazz, check_effect_service, manifest, Service, UserClient, check_service_property
from syzgen.kext.helper import parse_signature, iterate_kext
from syzgen.parser.generate import genServicePoc, generateInterface, build_template, generateTestcases, generateConfig
from syzgen.debugger.lldbproxy import LLDBProxy, run_debugger
from syzgen.utils import loads, vmrun, dumps, demangle, isVmRunning, checkVM, addEntitlement, getConfigKey, fnv64
from syzgen.config import ServicePath, ModelPath, ResourcePath, TestCasePath, Options
from syzgen.analysis.infer import type_inference, rebuild_template, remove_error_syscall
from syzgen.parser.optimize import Context, reduce_syscalls, reduce_syscall, reduce_length
from syzgen.parser.interface import parse_log, Log, Syscall
from syzgen.parser.types import SimplifyError, BufferType, PtrType, StructType, int2bytes
from syzgen.parser.corpus import generate_corpus
from syzgen.analysis.linux_test import TestLinuxExecutorMain
from syzgen.analysis.ioctl import TestIOCTLExecutorMain

logger = logging.getLogger("syzgen")
logger.setLevel(logging.DEBUG)

def iterate_service(services_path, func):
    with open(services_path, "r") as fp:
        services = json.load(fp)

    for binary, kext, clazz in services:
        if not os.path.exists(os.path.join(ServicePath, clazz)):
            continue

        if func(binary, kext, clazz):
            return True

    return False

def iterate_client(services_path, func):
    with open(services_path, "r") as fp:
        services = json.load(fp)

    for binary, kext, clazz in services:
        if not os.path.exists(os.path.join(ServicePath, clazz)):
            continue

        service = loads(os.path.join(ServicePath, clazz))
        for client in service.userClients:
            if func(binary, kext, service, client):
                return True

    return False

def gen_template(serviceName=None, clientName=None, no_async=False, use_log=True, finalize=False, nobuild=False):
    for name in os.listdir(ServicePath):
        if name.startswith("."):
            continue
        if serviceName and serviceName != name:
            continue
        obj = loads(os.path.join(ServicePath, name))
        if obj is None:
            continue

        if isinstance(obj, Service):
            for client in obj.userClients:
                if clientName and client.metaClass != clientName:
                    continue
                print(client.repr())
                if os.path.exists(os.path.join(ServicePath, client.metaClass)):
                    dispathtable = loads(os.path.join(ServicePath, client.metaClass))
                    if dispathtable is None: continue
                    filename = generateInterface(obj, client, dispathtable, no_async=no_async, useLog=use_log, finalize=finalize)
                    if nobuild:
                        print("check template at %s" % filename)
                    else:
                        build_template(filename)

                        generateConfig(client)
                        addEntitlement(os.path.join(getConfigKey("syzkaller"), "bin", "darwin_amd64", "syz-executor"))
                    return
                else:
                    print("please run python main.py --find_table")

def genTestcaseNetwork():
    with open(os.path.join("workdir", "testcases", "IONetworkUserClient", "kernel_hook.log"), "w") as f:
        handle = random.randrange(0xff)
        # length = random.randrange(124)
        # letters = [i for i in range(0x61, 0x61+26)]
        # result_str = [random.choice(letters) for _ in range(length)] + [0x0]
        result_str = [ord(each) for each in "IONetworkStatsKey"] + [0x0]
        length = len(result_str)

        log = Log(selector=4, inputStruct=result_str, inputStructCnt=length, 
            outputStruct=[handle, 0, 0, 0], outputStructCnt=4)
        f.write(log.toTestcase())
        log = Log(selector=3, input=[handle, 0, 0, 0, 0, 0, 0, 0], inputCnt=1, 
            output=[1, 0, 0, 0, 0, 0, 0, 0], outputCnt=1)
        f.write(log.toTestcase())

def genTestcaseUSBHostDevice():
    with open(os.path.join("workdir", "testcases", "AppleUSBHostDeviceUserClient", "kernel_hook.log"), "w") as f:
        log = Log(selector=0, input=int2bytes(random.randrange(2), 8), inputCnt=1)
        f.write(log.toTestcase())

        descriptor = random.randrange(256)
        log = Log(selector=3, output=int2bytes(descriptor, 8), outputCnt=1)
        f.write(log.toTestcase())

        # log = Log(selector=2, input=int2bytes(descriptor, 8)+int2bytes(random.randrange(2), 8), inputCnt=2)
        # f.write(log.toTestcase())

def genTestcaseAppleUpstreamUserClient():
    with open(os.path.join("workdir", "testcases", "AppleUpstreamUserClient", "kernel_hook.log"), "w") as f:
        link = random.randrange(16)
        log = Log(selector=0, output=int2bytes(link, 8), outputCnt=1)
        f.write(log.toTestcase())

        log = Log(selector=5, input=int2bytes(link, 8), inputCnt=1)
        f.write(log.toTestcase())

def parse_testcase(logdir):
    # collect logs
    all_logs = dict()
    for name in os.listdir(logdir):
        print(name)
        if name.endswith(".log") and name.startswith("kernel_hook"):
            logger.debug("parsing %s" % name)
            ents = parse_log(os.path.join(logdir, name))
            all_logs[name] = ents

    all_syscalls = dict()
    for filename, ents in all_logs.items():
        all_syscalls[filename] = [ent.construct() for ent in ents]
        
    # save parsed logs
    for name, ents in all_syscalls.items():
        dumps(os.path.join(logdir, "out_%s" % name), ents)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="main")
    parser.add_argument('-b', '--binary', help="path to binary")
    parser.add_argument('-t', '--test', default=False, action="store_true", help="for testing only")
    parser.add_argument('-s', '--static', default=False, action="store_true", help="perform static analysis")
    parser.add_argument('-d', '--dynamic', default=False, action="store_true", help="dynamic analysis")
    parser.add_argument('-m', '--manifest', default=False, action="store_true", help="manifest all services")
    parser.add_argument('-p', '--package', help="package name for the kext")
    parser.add_argument('-c', '--client', help="client class")
    parser.add_argument('--config', default="config", help="path to the config file")
    parser.add_argument('--service', help="service class")
    parser.add_argument('--find_service', action="store_true", default=False, help="find services")
    parser.add_argument('--find_client', action="store_true", default=False, help="find user clients")
    parser.add_argument('--find_table', action="store_true", default=False, help="find the dispathtable for clients")
    parser.add_argument('--gen_template', action="store_true", default=False, help="generate default template")
    parser.add_argument('--infer_type', action="store_true", default=False, help="type inference")
    parser.add_argument('--dir', default="10.15.4", help="path to the dir of kext")
    parser.add_argument('--manual', default=False, action="store_true", help="manually launch debugger")
    parser.add_argument('--show', default=False, action="store_true", help="show client and service")
    parser.add_argument('--no_async', default=False, action="store_true", help="do not need async methods")
    parser.add_argument('--runInHost', default=False, action="store_true", help="test service in host")
    parser.add_argument('--find_class', help="find class")
    parser.add_argument('--find_entitlement', default=False, action="store_true", help="find entitlements")
    parser.add_argument('--gen_corpus', default="", help="generate valid testcases")
    parser.add_argument('--timeout', default=0, type=int, help="set timeout (s)")
    parser.add_argument('--no_mem', default=False, action="store_true", help="do not inspect memory when analyzing dispatch table")
    parser.add_argument('--no_log', default=False, action="store_true", help="do no analyze logs")
    parser.add_argument('--finalize', default=False, action="store_true", help="finalize specification")
    parser.add_argument('--no_infer', default=False, action="store_true")
    parser.add_argument('--rebuild_template', default=False, action="store_true")
    parser.add_argument('--nobuild', default=False, action="store_true", help="do not compile the template")
    parser.add_argument('--debug', default=False, action="store_true", help="print debug info to file output.log")

    args = parser.parse_args()
    Utils.CONFIG_PATH = args.config
    options = Options()
    if args.no_infer:
        options.infer_dependence = False

    if args.debug:
        handler = logging.FileHandler("output.log", "w+")
        handler.setFormatter(logging.Formatter())
        logging.getLogger().addHandler(handler)

    if args.find_service or args.find_client or args.infer_type or args.find_table:
        if not isVmRunning():
            vmrun("start")
            time.sleep(60)
        checkVM()

    if args.find_client or args.find_entitlement or args.find_table or args.infer_type or \
        args.gen_corpus or args.rebuild_template:
        services_path = os.path.join("workdir", "services.json")
        if not os.path.exists(services_path):
            logger.error("please run with --find_service first")
            exit(0)

    if args.infer_type or args.dynamic:
        if args.dir is None:
            logger.info("dir is None")
            exit(0)

    if args.find_service:
        services = list()
        def analysis(binary, kext):
            for clazz in findAllService(binary):
                services.append((binary, kext, clazz))

        iterate_kext(args.dir, analysis)
        print("found %d services" % len(services))
        for binary, kext, clazz in services:
            print(binary, kext, clazz)

        with open(os.path.join("workdir", "services.json"), "w") as fp:
            json.dump(services, fp, indent=2)
    elif args.find_entitlement:
        entitlements = set()
        with open(services_path, "r") as fp:
            services = json.load(fp)

        checked = set()
        for binary, _, _ in services:
            if binary not in checked:
                checked.add(binary)
                entitlements.update(find_entitlement(binary))

        for each in entitlements:
            print(each)
    elif args.find_class:
        def analysis(binary, kext):
            proj = angr.Project(binary)
            for sym in proj.loader.main_object.symbols:
                if args.find_class in sym.name:
                    print(binary, kext, sym.name)
                    return True

        iterate_kext(args.dir, analysis)
    elif args.find_client:
        proxy = LLDBProxy()
        try:
            with open(services_path, "r") as fp:
                services = json.load(fp)

            for binary, kext, clazz in services:
                if args.service and clazz != args.service:
                    continue

                if os.path.exists(os.path.join(ServicePath, clazz)):
                    logger.debug("skip %s" % clazz)
                    continue

                service = parse_service(binary, clazz)
                if service.newUserClient == 0:
                    # User client is registered in the property.
                    find_default_client(binary, kext, service, args.dir)
                else:
                    if not find_client(proxy, binary, kext, service, args.dir):
                        # By inspecting the binary code of AppleMCCSControlFamily (newUserClient),
                        # it shouldn't succeed to return a user client, but somehow it does.
                        # Before we figure out, we fall back to the default way.
                        find_default_client(binary, kext, service, args.dir)

                print(service.repr())
        finally:
            proxy.exit()
    elif args.find_table:
        proxy = LLDBProxy()
        try:
            with open(services_path, "r") as fp:
                services = json.load(fp)

            for binary, kext, clazz in services:
                if args.service and clazz != args.service:
                    continue
                if not os.path.exists(os.path.join(ServicePath, clazz)):
                    continue

                service = loads(os.path.join(ServicePath, clazz))
                for client in service.userClients:
                    if args.client and args.client != client.metaClass:
                        continue

                    path = os.path.join(ServicePath, client.metaClass)
                    if os.path.exists(path):
                        logger.debug("skip %s:%s" % (clazz, client.metaClass))
                        continue

                    table = find_dispatchTable(proxy, binary, kext, service, client, args.no_mem)
                    if table:
                        print(table.repr())
                        dumps(path, table)
                    else:
                        print("[Dynamic] failed to find functionalities for %s:%s" % (clazz, client.metaClass))
                        # try to use static analysis, which is less precise and uses heuristics.
                        table = analyze_externalMethod(binary, service, client)
                        if table:
                            print(table.repr())
                            dumps(path, table)
                        else:
                            print("[Static] failed to find functionalities for %s:%s" % (clazz, client.metaClass))

        finally:
            proxy.exit()

    elif args.manifest:
        manifest(args.client)
    elif args.gen_template:
        gen_template(args.service, args.client, no_async=args.no_async, use_log=not args.no_log, finalize=args.finalize, nobuild=args.nobuild)
    elif args.infer_type:
        proxy = LLDBProxy()
        try:
            def analysis(binary, kext, service, client):
                if args.service and service.metaClass != args.service:
                    return
                if args.client and client.metaClass != args.client:
                    return

                model = loads(os.path.join(ModelPath, client.metaClass))
                if model is None:
                    raise Exception("Please generate the default template first")
                type_inference(binary, kext, service, client, debugger=proxy, manual=args.manual, timeout=args.timeout)
                return True

            iterate_client(services_path, analysis)
        finally:
            proxy.exit()
    elif args.rebuild_template:
        def analysis(binary, kext, service, client):
            if args.service and service.metaClass != args.service:
                return
            if args.client and client.metaClass != args.client:
                return
            rebuild_template(service, client, finalize=args.finalize)
            generateConfig(client)
            addEntitlement(os.path.join(getConfigKey("syzkaller"), "bin", "darwin_amd64", "syz-executor"))
            return True

        iterate_client(services_path, analysis)

    elif args.show:
        def show(binary, kext, service, client):
            if args.client and args.client != client.metaClass:
                return
            dispathtable = loads(os.path.join(ServicePath, client.metaClass))
            if dispathtable is None: return
            print(client.repr())
            print(dispathtable.repr())

        iterate_client(os.path.join("workdir", "services.json"), show)
    elif args.gen_corpus:
        if args.client:
            def analysis(binary, kext, service, client):
                if client.metaClass != args.client:
                    return
                generate_corpus(args.gen_corpus, client)

            iterate_client(services_path, analysis)
    elif args.test:
        pass
