 #!/usr/bin/env bash

# Get script current path
CURRENT_PATH="$(dirname ${BASH_SOURCE[0]:-$0})"

export PATH="$CURRENT_PATH/install/bin/:$PATH"
alias pip3="$CURRENT_PATH/install/bin/python3 -m pip"
