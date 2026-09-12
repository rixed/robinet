#!/bin/sh

set -e

PORT=${PORT:-8080}
API="http://localhost:$PORT/api"
TOPOLOGY=$(dirname "$0")/transatlantic.json

# Talk to the administration API.  Anything that is not a success is fatal, and
# what the API sends back is what says why: its errors are JSON with an "error"
# in them, and they are worth reading in full rather than reduced to a code.
#
# A third argument is the request body, and "@-" reads it from stdin, as curl
# has it.
api() { # method path [body|@-]
  method=$1
  path=$2
  tmp=$(mktemp)
  if [ $# -lt 3 ] ; then
    status=$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" "$API$path")
  else
    status=$(curl -sS -o "$tmp" -w '%{http_code}' -X "$method" \
                  -H 'Content-Type: application/json' \
                  --data-binary "$3" "$API$path")
  fi
  case $status in
    2*) cat "$tmp" ; rm -f "$tmp" ;;
    *)  echo "$method $path answered $status:" >&2
        cat "$tmp" >&2 ; echo >&2
        rm -f "$tmp"
        exit 1 ;;
  esac
}

# The id of the widget of $SIM at path $1, which is where a cable or a
# property is then addressed by: the routes take the numeric id and nothing
# else, and "?path=" on the collection is the one place a path is understood.
#
# It answers with an array of the widgets matching, which is at most one --
# siblings differ in name -- so the id wanted is the one at the front of it,
# and a path naming nothing comes back as "[]" and so as no id at all.
widget_id() { # path below the simulation root
  api GET "/simulations/$SIM/widgets?path=/$SIM_NAME/$1" |
    sed -n 's/^\[{"id":\([0-9][0-9]*\).*/\1/p'
}

sudo setcap cap_net_raw,cap_net_admin=eip examples/admin_demo.opt

echo "# Setup the interfaces..."

for loc in eu us ; do
  sudo ip netns add ns-$loc
  sudo ip link add veth-$loc-ns type veth peer name veth-$loc
  sudo ip link set veth-$loc-ns netns ns-$loc
  sudo ip link set veth-$loc up
  sudo ip netns exec ns-$loc ip link set veth-$loc-ns up
done

echo "# Waiting for the administration interface on port $PORT..."

tries=0
until curl -sSf -o /dev/null "$API/simulations" 2>/dev/null ; do
  tries=$((tries + 1))
  if [ $tries -ge 20 ] ; then
    echo "Nothing is serving the administration interface on port $PORT." >&2
    echo "Start one with: examples/admin_demo.opt $PORT" >&2
    echo "(or set PORT to wherever it is listening)" >&2
    exit 1
  fi
  sleep 1
done

echo "# Loading $TOPOLOGY..."

# A simulation of its own rather than a load into an existing one: the network
# is what is being asked for, and a document that will not load then leaves
# nothing behind.  It arrives paused, which is the next step.
created=$({ printf '{"topology":' ; cat "$TOPOLOGY" ; printf '}' ; } |
          api POST /simulations @-)

SIM=$(printf '%s' "$created" |
      sed -n 's/.*"simulation":{"id":\([0-9][0-9]*\).*/\1/p')
case $SIM in
  '') echo "Cannot tell which simulation was made from: $created" >&2 ; exit 1 ;;
esac

# And what it ended up being called, which is the first component of every path
# below: the document's own name, unless something already answered to it, in
# which case it was made unique and only the answer knows.
SIM_NAME=$(printf '%s' "$created" |
           sed -n 's/.*"simulation":{"id":[0-9]*,"name":"\([^"]*\)".*/\1/p')
case $SIM_NAME in
  '') echo "Cannot tell what simulation $SIM is called" >&2 ; exit 1 ;;
esac

# What the document asked for that would not take.  The network is still the
# one that was asked for, which is why this is worth saying and not worth
# stopping for.
case $created in
  *'"refused":[]'*) ;;
  *) echo "Warning: some of the network was refused:" >&2
     printf '%s\n' "$created" | tr ',' '\n' | grep -A99 '"refused"' >&2 ;;
esac

echo "# Simulation $SIM is up. Starting its clock..."

api POST "/simulations/$SIM/resume" > /dev/null

# Powering a portal up opens the real interface of that name, which is what
# turns this simulation into a real time one.  The interfaces above have to
# exist by now, which they do.
for loc in eu us ; do
  id=$(widget_id "veth-$loc")
  case $id in
    '') echo "The network has no portal called veth-$loc." >&2 ; exit 1 ;;
  esac
  echo "# Powering up portal veth-$loc (widget $id)..."
  api PUT "/simulations/$SIM/widgets/$id/properties/on" true > /dev/null
done

echo "# The network is running: http://localhost:$PORT/"

echo "# Start DHCP client"
for loc in eu us ; do
  sudo nsenter --net=/var/run/netns/ns-$loc udhcpc -i veth-$loc-ns -q
done

echo "Press a key to delete all the portals..."
read REPLY

echo "# Destroying the portals..."
for loc in eu us ; do
  sudo ip netns del ns-$loc
done
