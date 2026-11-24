import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import numpy as np

from vulnminer.catalog import catalog
from vulnminer.cli import main
from vulnminer.reporting import write_reports
from vulnminer.scanner import scan, load_model

ROOT=Path(__file__).resolve().parents[1]


class FunctionalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report=scan(ROOT/'examples'/'tienda-demo')

    def test_coverage_and_locations(self):
        report=self.report
        web={l for f in report['findings'] for l in f['owasp_top10']}
        api={l for f in report['findings'] for l in f['owasp_api']}
        self.assertGreaterEqual(len(web),5)
        self.assertGreaterEqual(len(api),4)
        self.assertEqual(len(report['services']),2)
        for finding in report['findings']:
            source=(ROOT/'examples'/'tienda-demo'/finding['file']).read_text(encoding='utf-8').splitlines()
            self.assertEqual(source[finding['line']-1].strip(),finding['evidence'])
            self.assertFalse(finding['confirmed'])
            self.assertTrue(finding['recommendation'])
            self.assertTrue(finding['severity_justification'])

    def test_safe_pairs_and_metadata_are_not_findings(self):
        self.assertTrue(self.report['findings'])
        self.assertTrue(all('_risk.' in f['file'] for f in self.report['findings']))

    def test_twenty_categories_and_unevaluated(self):
        self.assertEqual(len(catalog()),20)
        self.assertTrue(any('No evaluada' in c['status'] for c in catalog()))

    def test_standards_filter(self):
        report=scan(ROOT/'examples'/'tienda-demo',standards=['api2023'])
        self.assertTrue(report['findings'])
        self.assertTrue(all(not f['owasp_top10'] for f in report['findings']))
        self.assertEqual(len(report['catalog']),10)

    def test_abstention_and_model_is_required_for_labels(self):
        model=load_model()
        class NegativeClassifier:
            def predict_proba(self,matrix):
                return np.zeros((matrix.shape[0],len(model['classes'])))
        model['estimator']=NegativeClassifier()
        with patch('vulnminer.scanner.load_model',return_value=model):
            report=scan(ROOT/'examples'/'tienda-demo')
        self.assertTrue(report['findings'])
        self.assertTrue(all(not f['owasp_top10'] and not f['owasp_api'] for f in report['findings']))
        self.assertTrue(all(f['verification_status']=='Pendiente de revision' for f in report['findings']))

    def test_json_html_escape_and_schema(self):
        with tempfile.TemporaryDirectory() as folder:
            report=json.loads(json.dumps(self.report))
            report['findings'][0]['context']='<script>alert("x")</script>'
            paths=write_reports(report,folder,['json','html'])
            self.assertEqual(len(paths),2)
            restored=json.loads((Path(folder)/'analisis.json').read_text(encoding='utf-8'))
            self.assertEqual(restored['schema_version'],'1.0')
            document=(Path(folder)/'analisis.html').read_text(encoding='utf-8')
            self.assertIn('&lt;script&gt;',document)
            self.assertNotIn('<script>alert(',document)

    def test_exclusions_large_files_unknown_patterns(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'node_modules').mkdir()
            (root/'node_modules'/'ignored.py').write_text('eval(user_input)',encoding='utf-8')
            (root/'huge.py').write_text('x'*1_000_001,encoding='utf-8')
            (root/'review.py').write_text('eval(user_input)',encoding='utf-8')
            report=scan(root)
            self.assertEqual(report['files_analyzed'],1)
            self.assertEqual(len(report['skipped_files']),1)
            self.assertEqual(report['findings'][0]['verification_status'],'Pendiente de revision')

    def test_configuration_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'application.yml').write_text('service: shipment\ndebug: true\n',encoding='utf-8')
            report=scan(root)
            self.assertEqual(report['files_analyzed'],1)
            self.assertTrue(report['findings'])
            self.assertEqual(report['findings'][0]['line'],2)

    def test_invalid_path_and_cli_codes(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['scan',str(ROOT/'does-not-exist')]),2)
            with self.assertRaises(SystemExit) as error:
                main(['scan','--format','pdf'])
            self.assertEqual(error.exception.code,2)
        with tempfile.TemporaryDirectory() as folder,contextlib.redirect_stdout(io.StringIO()):
            code=main(['scan',str(ROOT/'examples'/'tienda-demo'),'--output',folder,'--fail-on-findings'])
            self.assertEqual(code,1)
            self.assertTrue((Path(folder)/'analisis.json').is_file())

    def test_dataset_independence(self):
        import pandas as pd
        df=pd.read_csv(ROOT/'data'/'dataset.csv',keep_default_na=False)
        self.assertGreaterEqual(len(df),500)
        self.assertGreaterEqual((df.vulnerable==0).sum(),100)
        self.assertFalse(df.sha256.duplicated().any())
        self.assertEqual(df.groupby('project').split.nunique().max(),1)
        self.assertTrue(set(df[df.split=='train'].family).isdisjoint(set(df[df.split=='test'].family)))


if __name__=='__main__':
    unittest.main()
