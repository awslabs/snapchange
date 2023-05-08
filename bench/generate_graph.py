"""
pip3 install seaborn
"""

import pandas
import matplotlib
import matplotlib.pyplot as plt
import seaborn as sns
import sys


# Get the data file from the command line
data_file = sys.argv[1]

# Either instrs or bps here
bps_or_instrs = 'instrs'

# Either exec_sec or exec_sec_core hre
y_axis = 'exec_sec_core'

# Read the data from the given files
data = pandas.read_csv(data_file).query(f"{bps_or_instrs} > 0 and exec_sec > 0")
print(data)

# Create the FacetGrd
# grid = sns.FacetGrid(data, row="pages", col=bps_or_instrs, hue="processor", height=3, sharey=False).set(xscale='log', yscale='log')
grid = sns.FacetGrid(data, row="pages", col=bps_or_instrs, height=3, sharey=False).set(xscale='log', yscale='log')

# Scatterplot all of the facets with Cores on x axis and exec/sec(/core) on y
grid.map(sns.scatterplot, "cores", y_axis)
grid.add_legend()

# Replace all numbers with shortened numbers in the Facet titles
# Ex: 1000000 -> 1M
# Ex: 5000    -> 5K
for grids in grid.axes:
    for curr_grid in grids:
        text = curr_grid.title.get_text()
        nums = []
        for item in text.split():
            try:
                num = int(item)
                nums.append(num)
            except:
                pass

        for num in reversed(sorted(nums)):
            for (check_val, unit) in [(1000000000, 'G'), (1000000, 'M'), (1000, 'K')]:
                if num >= check_val:
                    new_num = f'{num / check_val}{unit}'
                    text = text.replace(str(num), new_num)
                    break

        # Re-write the text with the shortened numbers
        curr_grid.title.set_text(text)

        # Ensure to not use scientific notation on the y axis
        curr_grid.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda y, p: f'{y:.1f}'))

        curr_grid.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda y, p: f'{y:.0f}'))

        # Do not print the minor ticks on x or y axis
        curr_grid.yaxis.set_minor_formatter(matplotlib.ticker.FuncFormatter(lambda y, p: ''))
        curr_grid.xaxis.set_minor_formatter(matplotlib.ticker.FuncFormatter(lambda y, p: ''))

        # Set the top of the y axis to a multiple of 10 for a bit nicer looking y axis
        (bottom, top) = curr_grid.set_ylim()
        if top <= 1:
            top = 1.0
        elif top <= 10:
            top = 10.0
        elif top <= 100:
            top = 100.0
        elif top <= 1000:
            top = 1000.0
        elif top <= 10000:
            top = 10000.0
        curr_grid.set_ylim(0.1, top)


# Save the graph to disk
outfile = f"data_{bps_or_instrs}_{y_axis}.svg"
print(f"Graph saved to {outfile}")
matplotlib.pyplot.savefig(outfile)
