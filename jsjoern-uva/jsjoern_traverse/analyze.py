#!/usr/bin/env python3
import sys
import graph
import check
import os
import traceback
import argparse
from esprima import esprima_parse
import uuid

def analyze(path, sink_funcs=[]):
    try:
        tmp_dir = f'jsjoern-tmp/{uuid.uuid4()}'
        os.makedirs(tmp_dir, exist_ok=True)
        base_path = os.path.abspath(__file__)
        abs_package_path = os.path.abspath(path)
        code = f'var a=require("{abs_package_path}");'
        log = esprima_parse('-', args=['-o', tmp_dir], input=code,
            print_func=lambda x: None)
        joern_path = os.path.normpath(base_path + '/../../phpast2cpg')
        os.system(f'"{joern_path}" {tmp_dir}/nodes.csv {tmp_dir}/rels.csv '
                  f'{tmp_dir}/cpg_edges.csv >/dev/null 2>&1')
        results = check.check(tmp_dir, sink_funcs)
        if results:
            return 1 
        else:
            return 0 
    except Exception as e:
        traceback.print_exc()
        return traceback.format_exc()

def count(path):
    try:
        tmp_dir = f'jsjoern-tmp/{uuid.uuid4()}'
        os.makedirs(tmp_dir, exist_ok=True)
        base_path = os.path.abspath(__file__)
        abs_package_path = os.path.abspath(path)
        code = f'var a=require("{abs_package_path}");'
        log = esprima_parse('-', args=['-o', tmp_dir], input=code,
            print_func=lambda x: None)
        joern_path = os.path.normpath(base_path + '/../../phpast2cpg')
        os.system(f'"{joern_path}" {tmp_dir}/nodes.csv {tmp_dir}/rels.csv '
                  f'{tmp_dir}/cpg_edges.csv >/dev/null 2>&1')
        g = graph.Graph()
        g.import_from_CSV(os.path.normpath(tmp_dir + '/nodes.csv'),
                      os.path.normpath(tmp_dir + '/rels.csv'),
                      os.path.normpath(tmp_dir + '/cpg_edges.csv'))
        return g.count()
    except Exception as e:
        return None, None, None, None

def main():
    base_path = os.path.abspath(__file__)
    argparser = argparse.ArgumentParser()
    argparser.add_argument('input', help='input file or directory')
    argparser.add_argument('-s', '--sink', metavar='sink function', nargs='*',
        default=['exec', 'spawn', 'execSync', 'spawnSync', 'execFile'])
    args = argparser.parse_args()

    filename = args.input.split("/")[-1].strip()
    if len(filename) < 2:
        filename = args.input.split("/")[-1].strip()

    tmp_dir = f'jsjoern-tmp/{filename}'

    # tmp_dir = f'jsjoern-tmp/{uuid.uuid4()}'
    os.makedirs(tmp_dir, exist_ok=True)
    base_path = os.path.abspath(__file__)
    abs_package_path = os.path.abspath(args.input)
    code = f'var a=require("{abs_package_path}");'
    log = esprima_parse('-', args=['-o', tmp_dir], input=code)
    print(log)
    joern_path = os.path.normpath(base_path + '/../../phpast2cpg')
    os.system(f'"{joern_path}" {tmp_dir}/nodes.csv {tmp_dir}/rels.csv '
                f'{tmp_dir}/cpg_edges.csv')
    print()
    results = check.check(tmp_dir, args.sink)
    print('Results:')
    print(results)
    c = count(args.input)
    print('AST edges:', c[0])
    print('CF edges:', c[1])
    print('DF edges:', c[2])
    print('Call edges:', c[3])

if __name__ == '__main__':
    main()
