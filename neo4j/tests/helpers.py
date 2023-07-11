def assert_all_contain(value, iterable):
    contains_value = [value in i for i in iterable]
    assert False not in contains_value
