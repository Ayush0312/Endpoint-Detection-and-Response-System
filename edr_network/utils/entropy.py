import re

def is_high_entropy(domain):
    return bool(re.match(r'[a-z0-9]{20,}', domain.replace('.', '')))

