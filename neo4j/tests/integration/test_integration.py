from src.integration.integration import relative_paths


def test_relative_paths_1():
    files = [
        '/var/www/html/filesystem01/test.php',
        '/var/www/html/filesystem01/foo/test.php',
    ]

    rels = relative_paths(files)
    assert 'test.php' == rels[0]
    assert 'foo/test.php' == rels[1]


def test_relative_paths_2():
    files = [
        'navex_docker/tempApp/filesystem01',
        'navex_docker/tempApp/filesystem01/foo',
        'navex_docker/tempApp/filesystem01/js',
        'navex_docker/tempApp/filesystem01/js/test.js',
    ]

    rels = relative_paths(files)
    assert '.' == rels[0]
    assert 'foo' == rels[1]
    assert 'js' == rels[2]
    assert 'js/test.js' == rels[3]
