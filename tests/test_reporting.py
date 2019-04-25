# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import json
import mock
import os.path
import pytest
import responses
import tempfile

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError
from cuckoo.common.files import Folders
from cuckoo.core.init import write_cuckoo_conf
from cuckoo.core.plugins import RunReporting
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, cwd, is_linux
from cuckoo.reporting.feedback import Feedback
from cuckoo.reporting.maecreport import MaecReport
from cuckoo.reporting.misp import MISP
from cuckoo.reporting.mongodb import MongoDB
from cuckoo.reporting.singlefile import SingleFile

def test_init():
    p = Report()
    p.set_options({
        "rep": "ort",
    })
    assert p.options["rep"] == "ort"
    assert p.options.rep == "ort"

def task(task_id, options, conf, results, filename="a.txt"):
    Folders.create(cwd(), ["conf", "storage"])
    Folders.create(cwd("storage"), ["analyses", "binaries"])
    Folders.create(cwd("storage", "analyses"), "%s" % task_id)
    Folders.create(cwd("storage", "analyses", "%s" % task_id), [
        "reports"
    ])

    write_cuckoo_conf({
        "reporting": conf,
    })

    task = {
        "id": task_id,
        "options": options,
        "target": filename,
    }
    RunReporting(task, results).run()

def test_empty_json():
    set_cwd(tempfile.mkdtemp())

    conf = {
        "jsondump": {
            "enabled": True,
        },
    }
    report_path = cwd("reports", "report.json", analysis=1)

    task(1, {}, conf, {})
    assert open(report_path, "rb").read() == "{}"

def test_unicode_json():
    set_cwd(tempfile.mkdtemp())

    conf = {
        "jsondump": {
            "enabled": True,
            "indent": 2,
        },
    }
    report_path = cwd("reports", "report.json", analysis=1)

    task(1, {}, conf, {
        "a": u"\u1234 \uecbc\uee9e",
    })
    assert open(report_path, "rb").read() == (
        '{\n  "a": "\\u1234 \\uecbc\\uee9e"\n}'
    )

def test_nonascii_json():
    set_cwd(tempfile.mkdtemp())

    conf = {
        "jsondump": {
            "enabled": True,
        },
    }
    report_path = cwd("reports", "report.json", analysis=1)

    task(1, {}, conf, {
        "a": "".join(chr(x) for x in range(256)),
    })
    buf = open(report_path, "rb").read()
    assert buf.startswith('{\n    "a": "\\u0000\\u0001\\u0002')
    assert buf.endswith('\\u00fd\\u00fe\\u00ff"\n}')

@responses.activate
def test_empty_mattermost():
    set_cwd(tempfile.mkdtemp())
    conf = {
        "mattermost": {
            "enabled": True,
            "url": "http://localhost/matter",
        },
    }
    responses.add(responses.POST, "http://localhost/matter")
    task(1, {}, conf, {})
    assert len(responses.calls) == 1

    # TODO Somehow catch the exception.
    conf["mattermost"]["url"] = "http://localhost/matter2"
    responses.add(responses.POST, "http://localhost/matter2", status=403)
    task(1, {}, conf, {})
    assert len(responses.calls) == 2

@responses.activate
def test_empty_misp():
    """Merely connects to MISP and creates the new event."""
    set_cwd(tempfile.mkdtemp())
    conf = {
        "misp": {
            "enabled": True,
            "url": "https://misphost",
            "apikey": "A"*32,
            "mode": "",
        },
    }

    with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
        rsps.add(
            responses.GET, "https://misphost/servers/getVersion.json",
            json={
                "version": "2.4.56",
                "perm_sync": True,
            },
        )
        rsps.add(
            responses.GET, "https://misphost/attributes/describeTypes.json",
            json={
                "result": {
                    "categories": None,
                    "types": None,
                    "category_type_mappings": None,
                    "sane_defaults": True,
                },
            },
        )
        rsps.add(
            responses.POST, "https://misphost/events",
            json={
                "response": None,
            },
        )

        task(1, {}, conf, {})
        assert len(rsps.calls) == 3

def test_misp_sample_hashes():
    r = MISP()
    r.misp = mock.MagicMock()

    r.misp.add_hashes.return_value = None
    r.sample_hashes({
        "target": {
            "file": {
                "name": "foobar",
                "md5": "m d 5",
                "sha1": "sha one",
                "sha256": "sha 256",
            },
        },
    }, "event")
    r.misp.add_hashes.assert_called_once_with(
        "event", category="Payload delivery", filename="foobar",
        md5="m d 5", sha1="sha one", sha256="sha 256",
        comment="File submitted to Cuckoo"
    )

def test_misp_maldoc():
    r = MISP()
    r.misp = mock.MagicMock()
    r.misp.add_url.return_value = None

    r.maldoc_network({
        "signatures": [
            {
                "name": "foobar",
            },
            {
                "name": "malicious_document_urls",
                "marks": [
                    {
                        "category": "file",
                    },
                    {
                        "category": "url",
                        "ioc": "url_ioc",
                    }
                ],
            },
        ],
    }, "event")
    r.misp.add_url.assert_called_once_with("event", ["url_ioc"])

def test_misp_all_urls():
    r = MISP()
    r.misp = mock.MagicMock()
    r.misp.add_url.return_value = None

    r.all_urls({
        "network": {
            "http_ex": [
                {
                    "protocol": "http",
                    "host": "hello",
                    "uri": "/bar",
                },
            ],
            "https_ex": [
                {
                    "protocol": "https",
                    "host": "hello",
                    "uri": "/foobar",
                },
            ],
        },
    }, "event")
    r.misp.add_url.assert_called_once_with(
        "event", [
            "http://hello/bar", "https://hello/foobar"
        ]
    )

def test_misp_domain_ipaddr():
    r = MISP()
    r.misp = mock.MagicMock()
    r.misp.add_domains_ips.return_value = None
    r.misp.add_ipdst.return_value = None

    r.domain_ipaddr({
        "network": {
            "domains": [
                {
                    "domain": "foobar",
                    "ip": "1.2.3.4",
                },
                {
                    # TODO Now that we have global whitelisting, this
                    # custom-made support for the MISP reporting module should
                    # probably be removed.
                    "domain": "time.windows.com",
                    "ip": "1.2.3.4",
                },
            ],
            "hosts": [
                "2.3.4.5",
                "3.4.5.6",
            ],
        },
    }, "event")
    r.misp.add_domains_ips.assert_called_once_with(
        "event", {
            "foobar": "1.2.3.4",
        },
    )
    r.misp.add_ipdst.assert_called_once_with(
        "event", ["2.3.4.5", "3.4.5.6"],
    )

def test_maec_empty_report():
    set_cwd(tempfile.mkdtemp())

    conf = {
        "maecreport": {
            "enabled": True,
        },
    }
    report_path = cwd("reports", "report.json", analysis=1)

    task(1, {}, conf, {})
    assert os.path.exists(report_path)
    assert open(report_path, "rb").read() == "{}"

@mock.patch("cuckoo.reporting.maecreport.MaecReport.create_obj_id")
def test_maec_create_obj_id(mock_create_obj_id):
    r = MaecReport()
    r.currentObjectIndex = mock.MagicMock()
    expected_value = "12"
    mock_create_obj_id.return_value = "12"

    id_returned = r.create_obj_id()
    assert expected_value == id_returned

#@mock.patch("cuckoo.reporting.maecreport.MaecReport.create_malware_instance")

def test_maec_create_malware_instance():
    r = MaecReport()
    r.currentObjectIndex = 0
    r.package = {"observable_objects": {}}
    test_file_data =  {
            "yara": [],
            "sha1": "fc45b50db30ad6cfd9220f282acbcb659bf916fc",
            "name": "test.bin",
            "type": "data",
            "sha256": "c0a86ac453f8216fa5081a647d188e82f17b3e6d9a5b02944b4558d9cbd7eb4b",
            "crc32": "E44BBC63",
            "sha512": "245202d8453dec655684e32f301ba58e67c4729e0847a5751fb712a1ada42ed9801237c5a9fb396ad0ae723a12f2407ac9773415776db384d0c298e9196bf603",
            "md5": "67a37542aaa213b335b45501c9686493",
            "size": 12
        }
    expected_value = collections.OrderedDict([('type', 'file'), ('name', 'test.bin'), 
        ('hashes', {'SHA-256': 'c0a86ac453f8216fa5081a647d188e82f17b3e6d9a5b02944b4558d9cbd7eb4b', 
        'SHA-512': '245202d8453dec655684e32f301ba58e67c4729e0847a5751fb712a1ada42ed9801237c5a9fb396ad0ae723a12f2407ac9773415776db384d0c298e9196bf603', 
        'SHA-1': 'fc45b50db30ad6cfd9220f282acbcb659bf916fc', 
        'MD5': '67a37542aaa213b335b45501c9686493'}), 
        ('size', 12), ('mime_type', None)])

    mal_instance = r.create_malware_instance(test_file_data)
    assert mal_instance['instance_object_refs'] ==  ['0']
    assert r.package['observable_objects']['0'] == expected_value
    


@mock.patch("cuckoo.reporting.maecreport.MaecReport.setup_primary_malware_instance")
def test_maec_setup_primary_malware_instance(mock_setup):
    r = MaecReport()
    r.package = mock.MagicMock()
    r.currentObjectIndex = 0
    result_sample = {
        'target' : {
            'category' : 'url',
            'url' : 'test.com'
        },
        'info' : {
            'version' : "1234"
        }

    }
    r.results = result_sample
    mal_instance = r.setup_primary_malware_instance()
    mock_setup.assert_called_once()


def test_add_dropped_files():
    r = MaecReport()
    r.package = {'relationships':[], "observable_objects": {}}
    r.results = {}
    r.currentObjectIndex = 0
    r.primaryInstance = {'id' : 'test'}
    r.results['dropped'] = [{
            "yara": [],
            "sha1": "fc45b50db30ad6cfd9220f282acbcb659bf916fc",
            "name": "test.bin",
            "type": "data",
            "sha256": "c0a86ac453f8216fa5081a647d188e82f17b3e6d9a5b02944b4558d9cbd7eb4b",
            "crc32": "E44BBC63",
            "sha512": "245202d8453dec655684e32f301ba58e67c4729e0847a5751fb712a1ada42ed9801237c5a9fb396ad0ae723a12f2407ac9773415776db384d0c298e9196bf603",
            "md5": "67a37542aaa213b335b45501c9686493",
            "size": 12
        }]
    r.add_dropped_files()
    assert len(r.package['relationships']) == 1
    


def test_maec_create_file_obj():
    r = MaecReport()
    r.currentObjectIndex= 0
    file_data =  {
            "yara": [],
            "sha1": "fc45b50db30ad6cfd9220f282acbcb659bf916fc",
            "name": "test.bin",
            "type": "data",
            "sha256": "c0a86ac453f8216fa5081a647d188e82f17b3e6d9a5b02944b4558d9cbd7eb4b",
            "crc32": "E44BBC63",
            "sha512": "245202d8453dec655684e32f301ba58e67c4729e0847a5751fb712a1ada42ed9801237c5a9fb396ad0ae723a12f2407ac9773415776db384d0c298e9196bf603",
            "md5": "67a37542aaa213b335b45501c9686493",
            "size" : 12
        }
    expected_return = ('0' , collections.OrderedDict([('type', 'file'), ('name', 'test.bin'), 
        ('hashes', {'SHA-256': 'c0a86ac453f8216fa5081a647d188e82f17b3e6d9a5b02944b4558d9cbd7eb4b', 
        'SHA-512': '245202d8453dec655684e32f301ba58e67c4729e0847a5751fb712a1ada42ed9801237c5a9fb396ad0ae723a12f2407ac9773415776db384d0c298e9196bf603', 
        'SHA-1': 'fc45b50db30ad6cfd9220f282acbcb659bf916fc', 
        'MD5': '67a37542aaa213b335b45501c9686493'}), 
        ('size', 12), ('mime_type', None)]))
    return_val = r.create_file_obj(file_data)
    assert expected_return == return_val


def test_maec_create_directory_obj():
    r = MaecReport()
    test_value = "/dir/test/sample"
    expected_value = {
            'type': 'directory',
            'path': "/dir/test/sample"
        }
    obj_returned = r.create_directory_obj(test_value)
    assert expected_value == obj_returned

def test_maec_create_process_obj():
    r = MaecReport()
    r.pidObjectMap = {}
    r.objectMap = {}
    r.currentObjectIndex = 0
    r.package = mock.MagicMock()
    initial_length = len(r.pidObjectMap)
    test_val = mock.MagicMock()

    r.create_process_obj(test_val)
    assert (initial_length + 1) == len(r.pidObjectMap)

@mock.patch("cuckoo.reporting.maecreport.MaecReport.create_network_obj")
def test_maec_create_network_obj(mock_network):
    r = MaecReport()
    test_value = mock.MagicMock()
    expected_value = "12"
    mock_network.return_value = "12"

    id_returned = r.create_network_obj(test_value)
    assert expected_value == id_returned

def test_maec_deduplicate_obj():
    r = MaecReport()
    obj_hash = json.dumps( {"test_key" : "test_value"} )
    expected_value = 12
    r.objectMap = {}
    r.objectMap[obj_hash] = expected_value

    returned_value = r.deduplicate_obj({"test_key" : "test_value"})
    assert returned_value == expected_value

@mock.patch("cuckoo.reporting.maecreport.MaecReport.post_process_object")
def test_maec_post_process_object(mock_process):
    r = MaecReport()
    expected_hash = json.dumps( {"test_key" : "test_value"} )
    mock_process.return_value = expected_hash

    #parameters
    obj = mock.MagicMock(name='obj_param')
    arguments = mock.MagicMock(name='arguments_param')

    return_val = r.post_process_object(obj, arguments)
    assert return_val == expected_hash

@mock.patch("cuckoo.reporting.maecreport.MaecReport.map_api_to_action")
def test_maec_map_api_to_action(mock_map):
    r = MaecReport()
    r.package = mock.MagicMock(name='package')
    expected_value = '7b6f7e9d-b9d7-482d-a195-30594901ab77'
    mock_map.return_value = expected_value

    #parameters
    mapping = mock.MagicMock(name='mapping')
    call = mock.MagicMock(name='call')

    return_val = r.map_api_to_action(mapping, call)
    assert expected_value == return_val

@mock.patch("cuckoo.reporting.maecreport.MaecReport.create_avc_class_obj_list")
def test_maec_create_avc_class_obj_list(mock_create):
    r = MaecReport()
    expected_value = ["test"]
    mock_create.return_value = expected_value

    cuckoo_dict = mock.MagicMock(name='cuckoo_virusToal_dict')
    returned_val = r.create_avc_class_obj_list()
    assert expected_value == returned_val


def test_maec_add_process_tree():
    r = MaecReport()
    r.primaryInstance = {}
    r.primaryInstance['dynamic_features'] = {}
    r.primaryInstance['dynamic_features']['process_tree'] = "test_wrong_type"
    r.results = mock.MagicMock()

    r.add_process_tree()
    assert isinstance(r.primaryInstance['dynamic_features']['process_tree'], list)

@mock.patch("cuckoo.reporting.maecreport.MaecReport.add_capabilities")
def test_maec_add_capabilities(mock_add):
    r = MaecReport()
    r.signature_names = mock.MagicMock(name='signature_names')

    r.add_capabilities()
    mock_add.assert_called_once()

@mock.patch("cuckoo.reporting.maecreport.MaecReport.create_directory_from_file_path")
def test_maec_create_directory_from_file_path(mock_create_dir_path):
    r = MaecReport()
    file_obj = mock.MagicMock(name='file_obj')
    path = mock.MagicMock(name='path')
    r.create_directory_from_file_path(file_obj, path)
    mock_create_dir_path.assert_called_once_with(file_obj, path)


@mock.patch("cuckoo.reporting.mongodb.mongo")
def test_mongodb_init_once_new(p):
    p.init.return_value = True
    MongoDB().init_once()
    p.db.collection_names.return_value = []
    p.db.cuckoo_schema.save.assert_called_once_with({
        "version": "1",
    })
    p.db.fs.files.ensure_index.assert_called_once()

@responses.activate
def test_almost_empty_notification():
    set_cwd(tempfile.mkdtemp())
    conf = {
        "notification": {
            "enabled": True,
            "url": "http://localhost/notification",
        },
    }
    responses.add(responses.POST, "http://localhost/notification")
    task(1, {}, conf, {})
    assert len(responses.calls) == 1
    assert responses.calls[0].request.body == "data=null&task_id=1"

    responses.add(responses.POST, "http://localhost/notification")
    task(1, {}, conf, {
        "info": {
            "id": 1,
        },
    })
    assert len(responses.calls) == 2
    assert sorted(responses.calls[1].request.body.split("&")) == [
        "data=%7B%22id%22%3A+1%7D", "task_id=1"
    ]

def test_feedback_empty():
    r = Feedback()
    r.set_path("tests/files/sample_analysis_storage")
    r.run({})

@mock.patch("cuckoo.reporting.feedback.CuckooFeedbackObject")
def test_feedback_not_enabled(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    r = Feedback()
    r.set_path("tests/files/sample_analysis_storage")
    r.run({
        "debug": {
            "errors": [
                "a", "b",
            ],
        },
    })
    p.assert_not_called()

@mock.patch("cuckoo.reporting.feedback.CuckooFeedbackObject")
@mock.patch("cuckoo.reporting.feedback.CuckooFeedback")
def test_feedback_enabled(p, q):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    r = Feedback()
    r.set_path("tests/files/sample_analysis_storage")
    r.run({
        "debug": {
            "errors": [
                "a", "b",
            ],
        },
    })
    q.assert_called_once()
    p.return_value.send_feedback.assert_called_once()

def test_empty_html():
    set_cwd(tempfile.mkdtemp())

    conf = {
        "singlefile": {
            "enabled": True,
            "html": True,
        },
    }
    task(1, {}, conf, {})
    assert os.path.exists(cwd("reports", "report.html", analysis=1))

if is_linux():
    def test_empty_pdf_linux():
        set_cwd(tempfile.mkdtemp())

        conf = {
            "singlefile": {
                "enabled": True,
                "html": False,
                "pdf": True,
            },
        }
        task(1, {}, conf, {})
        assert os.path.exists(cwd("reports", "report.pdf", analysis=1))
else:
    def test_empty_pdf_windows():
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "reporting": {
                "singlefile": {
                    "enabled": True,
                    "html": False,
                    "pdf": True,
                },
            },
        })
        sf = SingleFile()
        sf.set_path(cwd(analysis=1))
        sf.set_options({
            "html": True,
            "pdf": True,
        })
        sf.set_task({
            "id": 1,
            "target": "1.py",
        })
        with pytest.raises(CuckooReportError) as e:
            sf.run({})
        e.match("weasyprint library hasn't been installed")

class TestSingleFile(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        self.r = SingleFile()
        self.r.set_options({
            "html": True,
            "pdf": False,
        })

    def test_combine_images(self):
        assert len(self.r.combine_images().split("\n")) == 1

    def test_combine_screenshots(self):
        assert len(self.r.combine_screenshots({
            "screenshots": [{
                "path": "tests/files/sample_analysis_storage/shots/0001.jpg",
            }],
        })) == 1

    def test_combine_js(self):
        lines = self.r.combine_js().split("\n")
        assert "jQuery v2.2.4" in lines[0]
        assert "Stupid jQuery table plugin" in lines[2]

    def test_index_fonts(self):
        assert len(self.r.index_fonts()) == 5
