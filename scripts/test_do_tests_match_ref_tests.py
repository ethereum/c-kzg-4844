import ntpath
import posixpath
import types
import unittest
from unittest.mock import patch

import do_tests_match_ref_tests as script


class FindDataYamlTests(unittest.TestCase):
    def test_selects_mainnet_vectors_on_both_path_styles(self):
        for path in (posixpath, ntpath):
            with self.subTest(separator=path.sep):
                wanted = path.join("tests", "deneb", "kzg-mainnet", "case", "data.yaml")
                other = path.join("tests", "deneb", "kzg-minimal", "case", "data.yaml")
                with patch.object(script, "os", types.SimpleNamespace(path=path)):
                    with patch.object(script.glob, "glob", return_value=[wanted, other]):
                        self.assertEqual(script.find_data_yaml_files("tests"), [wanted])


if __name__ == "__main__":
    unittest.main()
