def multiline_to_list(data, whitespace_separator=True, unique_only=True):
    if whitespace_separator:
        data = data.replace(' ', '\n')
    data_list = data.replace('\r', '').split('\n')
    if unique_only:
        return list(set(data_list))
    return data_list


def cmp_to_key(cmp_func, getter=None):
    class K(object):
        def __init__(self, obj, *args):
            self.obj = obj

        def extract(self, obj):
            if getter:
                return getter(obj)
            return obj

        def __lt__(self, other):
            return cmp_func(self.extract(self.obj), self.extract(other.obj)) < 0

        def __gt__(self, other):
            return cmp_func(self.extract(self.obj), self.extract(other.obj)) > 0

        def __eq__(self, other):
            return cmp_func(self.extract(self.obj), self.extract(other.obj)) == 0

        def __le__(self, other):
            return cmp_func(self.extract(self.obj), self.extract(other.obj)) <= 0

        def __ge__(self, other):
            return cmp_func(self.extract(self.obj), self.extract(other.obj)) >= 0

        def __ne__(self, other):
            return cmp_func(self.extract(self.obj), self.extract(other.obj)) != 0
    return K


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]
