
# nvram boot-args="amfi_get_out_of_my_way=0x1"
# jtool2: http://www.newosxbook.com/tools/jtool.html
# ldid: http://www.saurik.com/id/8
# brew install ldid

all: testService registry

testService: testService.c ent.plist
	gcc $< -o $@ -framework IOKit
	ldid -Sent.plist testService
	../jtool2/jtool2 --sign testService --inplace

registry: registry.c
	gcc $< -o $@ -framework IOKit -framework CoreFoundation