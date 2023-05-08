import json
import os
import sys

if not os.path.exists('gdb.symbols.user'):
    print("gdb.symbols.user not found.. No need to combine symbols")
    sys.exit(1)

if not os.path.exists('gdb.symbols.root'):
    print("gdb.symbols.root not found.. No need to combine symbols")
    sys.exit(1)

user = eval(open('gdb.symbols.user', 'r').read())
root = eval(open('gdb.symbols.root', 'r').read())

data = {}
seen = []
for d in user:
    seen.append(d['symbol'])
    data[d['address']] = d['symbol']

for d in root:
    symbol = d['symbol']
    address = d['address']
    if address in data or symbol in seen:
        continue
    
    seen.append(symbol)
    data[address] = symbol

sorted_items = sorted(data.items())

final_results = []

for index in range(0, len(sorted_items) - 1):
    if index % 0x10 == 0:
        print(index)

    # Get the current and next symbol to calculate how 
    (curr_addr, s) = sorted_items[index]

    # Somehow no symbols for this address were added
    if len(s) == 0:
        continue

    # Add the symbol to the final database 
    final_results.append({
        "address": curr_addr, 
        "symbol": s
    })

symbols_file = "gdb.symbols"
print("Writing symbols to {}".format(symbols_file))
with open(symbols_file, 'w') as f:
    f.write(json.dumps(final_results))
