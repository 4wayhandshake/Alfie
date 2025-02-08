from urllib.parse import quote as urlencode

def identity(s):
    return s

def urlencode_specialchars(s):
    """
    URL encode all special chars not used in regular URLs (like percent)
    """
    return urlencode(s)

def urlencode_special_and_slashes(s):
    encoded = urlencode_specialchars(s)
    fully_encoded = encoded.replace('/','%2f')
    return fully_encoded

def urlencode_morechars(s):
    """
    URL encode all special chars, including the ones allowed in regular URLs: -, _, ., ~
    """
    encoded = urlencode_specialchars(s)
    fully_encoded = (encoded
                     .replace('.', '%2e')
                     .replace('-', '%2d')
                     .replace('_', '%5f')
                     .replace('~', '%7e')
                     .replace('/', '%2f'))
    return fully_encoded


def double_urlencode_specialchars(s):
    """
    URL encode all special chars not used in regular URLs (like percent), then do it again!
    """
    return urlencode_specialchars(urlencode_specialchars(s))


def double_urlencode_morechars(s):
    """
    URL encode all special chars including -, _, ., and ~... then do it again!
    """
    return urlencode_morechars(urlencode_morechars(s))


def slash_bypass(s):
    return s.replace('/', '/./')
    
    
def backslashes(s):
    return s.replace('/','\\')
