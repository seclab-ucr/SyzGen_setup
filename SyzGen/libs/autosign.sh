if [ -z "$1" ]
then
	echo "Usage: ./autosign.sh filepath" && exit 1
else
	if [ -f "$1" ]; then
		echo "add entitlement and signature to ${1}..."
		ldid -Sent.plist $1
		../jtool2/jtool2 --sign $1 --inplace
		echo "Done!"
	else
		echo "${1} does not exist" && exit 2
	fi
fi