"""tidyreport — summarise the numeric columns of a CSV as a text table."""
from fx_csvparse import columns
from fx_stats import describe
from fx_table import render

HEADER = ["column", "n", "mean", "stdev", "min", "max"]


def summarize(csv_text, digits=2):
    rows = []
    for name, values in columns(csv_text).items():
        d = describe(values)
        if d["count"] == 0:
            continue
        rows.append([name, str(d["count"])] +
                    [f"{d[k]:.{digits}f}" for k in ("mean", "stdev", "min", "max")])
    return render(HEADER, rows)
