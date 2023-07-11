import os
import subprocess

main_js_path = os.path.realpath(os.path.join(__file__,
                                '../../esprima-joern/main.js'))
search_js_path = os.path.realpath(os.path.join(__file__,
                                '../../esprima-joern/search.js'))

def esprima_parse(path='-', args=[], input=None, print_func=print):
    # use "universal_newlines" instead of "text" if you're using Python <3.7
    #        ↓ ignore this error if your editor shows
    proc = subprocess.Popen(['node', main_js_path, path] + args, text=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(input)
    print_func(stderr)
    return stdout

def esprima_search(module_name, search_path, print_func=print):
    proc = subprocess.Popen(['node', search_js_path, module_name, search_path],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    print_func(stderr)
    main_path, module_path = stdout.split('\n')[:2]
    return main_path, module_path
