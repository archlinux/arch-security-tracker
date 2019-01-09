from html.parser import HTMLParser


class AssertionHTMLElement(object):
    def __init__(self, tag, attrs):
        self.tag = tag
        self.attrs = attrs
        self.data = None

    def __repr__(self):
        return f'tag: {self.tag} attrs: {self.attrs} data: {self.data}'

class AssertionHTMLParser(HTMLParser):
    SELF_CLOSING_TAGS = {
        "area", "base", "br", "col", "embed",
        "hr", "img", "input", "link", "meta",
        "param", "source", "track", "wbr"}

    def __init__(self):
        HTMLParser.__init__(self)

    def reset(self):
        self.elements = []
        self.processing = []
        HTMLParser.reset(self)

    def handle_starttag(self, tag, attrs):
        element = AssertionHTMLElement(tag=tag, attrs=attrs)
        if tag not in self.SELF_CLOSING_TAGS:
            self.elements.append(element)
            self.processing.append(element)

    def handle_endtag(self, tag):
        if tag in self.SELF_CLOSING_TAGS:
            # <hr/> will emit both starttag and endtag
            return
        elem = self.processing.pop()
        if elem.tag != tag:
            raise ValueError("tag {} ended by {}".format(elem.tag, tag))

    def handle_data(self, data):
        if not self.processing:
            return
        self.processing[-1].data = data.strip()

    def get_element_by_id(self, id):
        return next(iter(self.get_elements_by_attribute('id', id)), None)

    def get_elements_by_attribute(self, key, value):
        return list(filter(
            lambda e: any(filter(lambda attr: attr == (key, value), e.attrs)),
            self.elements))

    def get_elements_by_tag(self, tag):
        return list(filter(lambda e: e.tag == tag, self.elements))
