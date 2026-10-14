"""tidyreport tests, run by fx-minitest inside the sandbox."""
from fx_minitest import assert_close, assert_text_equal
from fx_csvparse import parse
from fx_stats import describe
from fx_table import render
from fx_unicodewidth import width

import tidyreport

DATA = "city,temp,rain\nOslo, 4.0 ,12\nLima,19.5,0\nPune,27.0,3\n"
TOKYO = "東京"  # two double-width code points


def test_parse_normalizes_cells():
    header, rows = parse("a , b\n 1,  2 \n\n")
    assert header == ["a", "b"] and rows == [["1", "2"]]


def test_describe_mean_and_stdev():
    d = describe(["1", "2", "3"])
    assert_close(d["mean"], 2.0)
    assert_close(d["stdev"], 1.0)


def test_describe_skips_non_numeric():
    assert describe(["x", "2", ""])["count"] == 1


def test_wide_char_width():
    assert width(TOKYO) == 4 and width("Oslo") == 4


def test_table_aligns_wide_chars():
    got = render(["city", "n"], [[TOKYO + "x", "1"], ["Oslo", "22"]])
    want = "city  | n\n------+---\n" + TOKYO + "x | 1\nOslo  | 22"
    assert_text_equal(got, want)


def test_summary_table():
    want = ("column | n | mean  | stdev | min  | max\n"
            "-------+---+-------+-------+------+------\n"
            "temp   | 3 | 16.83 | 11.73 | 4.00 | 27.00\n"
            "rain   | 3 | 5.00  | 6.24  | 0.00 | 12.00")
    assert_text_equal(tidyreport.summarize(DATA), want)
