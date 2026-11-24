"""Transformaciones compartidas por entrenamiento e inferencia."""
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion


def normalize(code):
    # Preserve security-significant constants (False, true, md5, algorithms, SQL).
    code = re.sub(r'(?m)^\s*(?:#|//).*$', '', code)
    return code.replace('\r\n', '\n').strip()


def make_features():
    return FeatureUnion([
        ('characters', TfidfVectorizer(preprocessor=normalize, analyzer='char', ngram_range=(3, 5), min_df=2, max_features=22000, sublinear_tf=True)),
        ('tokens', TfidfVectorizer(preprocessor=normalize, token_pattern=r'[A-Za-z_][A-Za-z_0-9]*|\$\{|[?=+]', ngram_range=(1, 2), min_df=2, max_features=8000, sublinear_tf=True, lowercase=False)),
    ])
