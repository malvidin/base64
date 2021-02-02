#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
from splunklib.six import text_type
from splunklib.searchcommands.internals import CsvDialect

from mime_command import decode_mime


def process_line(input_dict, encoded, decoded):
    try:
        if input_dict[encoded] and not input_dict[decoded]:
            input_dict[decoded] = decode_mime(input_dict[encoded]).replace('\x00', '\\x00')
    except:
        pass


def get_csv_writer(infile, outfile, *args):
    reader = csv.DictReader(infile, dialect=CsvDialect)
    header = reader.fieldnames
    for arg in args:
        if arg not in header:
            raise KeyError('{arg!r} from command line arguments not found in input CSV headers'.format(arg=arg))
    writer = csv.DictWriter(outfile, header, dialect=CsvDialect)
    writer.writeheader()
    return reader, writer


def main():
    parser = argparse.ArgumentParser(description='MIME base64 encoded input, return in decoded output')
    parser.add_argument(
        'encoded', type=text_type, nargs=1,
        help='Input string to MIME base64.')
    parser.add_argument(
        'decoded', type=text_type, nargs=1,
        help='Output only, any input here is ignored')

    parser.add_argument('-i', '--infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin,
                        help='Input CSV, defaults to stdin')
    parser.add_argument('-o', '--outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout,
                        help='Input CSV, defaults to stdout')
    args = parser.parse_args()
    infile = args.infile
    outfile = args.outfile

    arg_list = [
        args.encoded[0],
        args.decoded[0],
    ]

    reader, writer = get_csv_writer(infile, outfile, *arg_list)
    for line in reader:
        process_line(line, *arg_list)
        writer.writerow(line)


if __name__ == '__main__':
    main()
