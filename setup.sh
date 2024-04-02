SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
echo "executing bash script located in ${SCRIPT_DIR}"
if [ -f ${SCRIPT_DIR}/venv/Scripts/activate ]; then
	source ${SCRIPT_DIR}/venv/Scripts/activate
	PATH=${SCRIPT_DIR}/venv/Scripts:${PATH}
elif [ -f ${SCRIPT_DIR}/venv/bin/activate ]; then
	source ${SCRIPT_DIR}/venv/bin/activate
else
	echo "no venv found, please check"
fi
