#!/bin/sh
# Installs Bend: `curl -fsSL https://bend-lang.com/install.sh | sh`.
# Installs Bun if missing, writes the launcher below to ~/.bend/bin/bend (a
# sibling file moved into place, so a killed install leaves the old one) and
# runs it once, which fetches the current release. Compiling to a binary
# needs clang 19+; a ! needs Metal (macOS) or CUDA 12 (Linux). The body
# is a function, so a cut download runs nothing.
main() {
set -e
B=${BEND_HOME:-$HOME/.bend}
command -v bun >/dev/null || curl -fsSL https://bun.sh/install | bash
mkdir -p "$B/bin"
cat > "$B/bin/bend.new" <<'EOF'
#!/bin/sh
# bend, the launcher. A run POSTs {id, ver, os, arch, cmd, exit, ms} to
# $BEND_ORIGIN/ping in the background (cmd: the first argument when it is
# an option, guide or base, else "run"; exit, ms: the previous run's, from
# `last`) and saves its reply {ver, url, sha256, notice} (or, when it names
# no ver, GET $O/dl/latest.json) as `rep`. The next run prints the notice
# and, when ver is not the installed one, fetches the tarball, checks its
# sha256, extracts it into a fresh dir under app/<ver> and renames a link
# to it onto `current`: runs at once each land whole, the last wins; a ver
# whose tarball failed the sha256 check (`bad`) is skipped. Nothing
# installed (or a dangling `current`) fetches latest.json at once, as
# `rep`. Under BEND_NO_TELEMETRY=1 an installed bend sends nothing and stays.
# Offline it runs what is installed.
set -u
B=${BEND_HOME:-$HOME/.bend}
O=${BEND_ORIGIN:-https://bend-lang.com}
BUN=$(command -v bun || echo "$HOME/.bun/bin/bun")
now() { n=$(date +%s%N); case $n in *[!0-9]*) n=$(date +%s)000000000;; esac; echo "${n%??????}"; }
get() { printf %s "$rep" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }
mkdir -p "$B/app"
if [ ! -f "$B/id" ]; then
  { cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen | tr A-Z a-z; } > "$B/id"
  echo "bend sends anonymous usage data and updates itself; BEND_NO_TELEMETRY=1 to opt out" >&2
fi
ver=$(readlink "$B/current" 2>/dev/null || true); ver=${ver%/*}; ver=${ver##*/}
[ -f "$B/current/bend2/main.ts" ] || ver=""
case ${1:-} in -*|guide|base) cmd=$(printf %s "$1" | sed 's/[\\"]/\\&/g');; *) cmd=run;; esac
rep=""
if [ -z "$ver" ]; then
  rep=$(curl -fs --max-time 5 "$O/dl/latest.json") && printf %s "$rep" > "$B/rep" 2>/dev/null
elif [ -z "${BEND_NO_TELEMETRY:-}" ]; then
  last=$(cat "$B/last" 2>/dev/null || echo "null null")
  ( r=$(curl -s --max-time 3 -H "Content-Type: application/json" "$O/ping" -d "{\"id\":\"$(cat "$B/id")\",\"ver\":\"$ver\",\"os\":\"$(uname -s)\",\"arch\":\"$(uname -m)\",\"cmd\":\"$cmd\",\"exit\":${last% *},\"ms\":${last#* }}")
    case $r in *'"ver":"'*) ;; *) r=$(curl -fs --max-time 3 "$O/dl/latest.json");; esac
    printf %s "$r" > "$B/rep.new" && mv -f "$B/rep.new" "$B/rep" ) </dev/null >/dev/null 2>&1 &
  rep=$(cat "$B/rep" 2>/dev/null || true)
fi
new=$(get ver); note=$(get notice | tr -d '\000-\037\177'); sha=$(get sha256)
[ -n "$note" ] && printf '%s\n' "$note" >&2
case $new in *[!0-9A-Za-z._-]*|.|..) new="";; esac
case $sha in *[!0-9a-f]*) sha="";; esac
[ ${#sha} -eq 64 ] || new=""
if [ -n "$new" ] && [ "$new" != "$ver" ] && [ "$new" != "$(cat "$B/bad" 2>/dev/null)" ] && mkdir -p "$B/app/$new" && tmp=$(mktemp -d "$B/app/$new/XXXXXX"); then
  sum=$(curl -fsL --max-time 120 -o "$tmp.tgz" "$(get url)" && { sha256sum < "$tmp.tgz" 2>/dev/null || shasum -a 256 < "$tmp.tgz"; })
  if [ "${sum%% *}" = "$sha" ] && tar -xzf "$tmp.tgz" -C "$tmp" && [ -f "$tmp/bend2/main.ts" ] \
    && ln -sfn "app/$new/${tmp##*/}" "$tmp.lnk" \
    && { [ ! -d "$B/current" ] || [ -L "$B/current" ] || mv "$B/current" "$B/current.$$"; } \
    && (cd "$B" && N="app/$new/${tmp##*/}.lnk" C=current "$BUN" -e 'require("fs").renameSync(process.env.N, process.env.C)'); then
    echo "bend updated to $new" >&2
  else
    rm -rf "$tmp" "$tmp.lnk"; [ -z "$sum" ] || echo "$new" > "$B/bad"
  fi
  rm -f "$tmp.tgz"
fi
[ -f "$B/current/bend2/main.ts" ] || { echo "bend: no release installed; is $O reachable?" >&2; exit 1; }
t0=$(now)
"$BUN" "$B/current/bend2/main.ts" "$@"
ex=$?
echo "$ex $(( $(now) - t0 ))" > "$B/last"
exit $ex
EOF
chmod +x "$B/bin/bend.new"
! [ -L "$B/bin/bend" ] || rm -f "$B/bin/bend"
mv -f "$B/bin/bend.new" "$B/bin/bend"
BEND_NO_TELEMETRY=1 "$B/bin/bend" --help >/dev/null 2>&1 || { echo "bend: no release from ${BEND_ORIGIN:-https://bend-lang.com}"; exit 1; }
old=$(command -v bend || true)
# the card: the wordmark and its block cursor, the dim notes, the welcome
b=$(printf '\033[1m') p=$(printf '\033[38;5;103m') d=$(printf '\033[38;5;245m')
r=$(printf '\033[0m') H=$(printf %s "$B" | sed "s|^$HOME|~|")
note() { printf '  %s%s%s\n' "$d" "$1" "$r"; }
printf '\n  %sBend%s %s\342\226\210%s  %s%s%s\n\n' "$b" "$r" "$p" "$r" "$d" \
  "$(sed -n 's/^const VERSION = "\(.*\)";$/\1/p' "$B/current/bend2/main.ts")" "$r"
note "Bend is installed at $H. Run ${p}bend guide$r$d to get started."
note "Bend sends anonymous usage data, unless BEND_NO_TELEMETRY=1."
case ":$PATH:" in
  *":$B/bin:"*) ;;
  *) case ${SHELL:-} in *zsh) rc=$HOME/.zshrc;; *bash) rc=$HOME/.bashrc;;
       *) rc=$HOME/.profile;; esac
     if grep -qs "$B/bin" "$rc" || printf '\nexport PATH="%s/bin:$PATH"\n' "$B" >> "$rc"; then
       note "Your PATH now has $H/bin; open a new shell to use bend."
     else
       note "Add $H/bin to your PATH."
     fi;;
esac
command -v cc >/dev/null || note "Install clang 19+ to build binaries."
[ -z "$old" ] || [ "$old" -ef "$B/bin/bend" ] || note "Another bend is at $old."
printf '\n  %sCongratulations! You'"'"'re now a %scode bender%s%s.%s\n\n' "$b" "$p" "$r" "$b" "$r"
}
main "$@"
