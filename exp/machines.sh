#!/bin/bash

echo
date
echo "$TITLE"

export eb1=10.142.0.3 # 35.190.146.32
export eb2=10.142.0.4 # 104.196.146.189
export eb3=10.142.0.5 # 104.196.197.124
export ec1=10.142.0.6 # 35.185.41.191
export ed1=10.142.0.7 # 104.196.179.173
export va1=10.150.0.3 # 35.188.244.89
export cc1=10.128.0.2 # 104.197.65.124
export wc1=10.138.0.2 # 35.185.215.189


for m in eb1 eb2 eb3 ec1 ed1 va1; do
  ssh $m "sudo ./src/go/bin/tao host stop >/dev/null 2>&1; pkill -f standalone; pkill -f offline_ca; pkill -f attested_; pkill -f tao" || true
done

if [[ "$TITLE" == "" ]]; then
  echo "no title, assuming same zone"
  export AA=eb1
  export BB=eb2
  export CC=eb3
elif [[ "$TITLE" == *"same machine"* ]]; then
  export AA=eb1
  export BB=eb1
  export CC=eb1
elif [[ "$TITLE" == *"same zone"* ]]; then
  export AA=eb1
  export BB=eb2
  export CC=eb3
elif [[ "$TITLE" == *"different zones"* ]]; then
  export AA=eb1
  export BB=ec1
  export CC=ed1
elif [[ "$TITLE" == *"east coast"* ]]; then
  export AA=eb1
  export BB=va1
  export CC=cc1
elif [[ "$TITLE" == *"wide area"* ]]; then
  export AA=eb1
  export BB=wc1
  export CC=cc1
else
  echo "bad DEPLOY"
fi

if [[ "$TITLE" == *"with resume"* ]]; then
  export resume="-tls_resume"
else
  unset resume
fi

if [[ "$TITLE" == *"with reconnect"* ]]; then
  export recon="-reconnect"
elif [[ "$TITLE" == *"with half-reconnect"* ]]; then
  export recon="-half_reconnect"
else
  unset recon
fi

eval export aa=\$$AA # pong server
eval export bb=\$$BB # ping client
eval export cc=\$$CC # central ca

ssh_fg() {
  mach="$1"
  eval addr="\$$mach"
  cmdline="$2"
  cmd=${cmdline/ *}
  echo "* Running $cmd on $mach ($addr): $cmdline"
  ssh -t $mach "bash -lc \"$cmdline\""
}

ssh_bg() {
  mach="$1"
  eval addr="\$$mach"
  cmdline="$2"
  cmd=${cmdline/ *}
  echo "* Running $cmd on $mach ($addr): $cmdline"
  ssh -t -f $mach "bash -lc \"$cmdline\""
  sleep 2
}


true
