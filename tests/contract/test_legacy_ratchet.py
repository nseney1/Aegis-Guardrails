"""Whole-tree vocabulary ratchet (ADR 0005 AD-6).

Count identifiers, text, comments, docstrings and file names in every Git-visible
file. Explicit history, immutable evidence and technical English exemptions are
recorded separately from per-file counts.

Threat model: accidental reintroduction. Deliberate obfuscation is outside scope.
Exemption policies and deferred count ceilings require source review to expand.

    PYTHONPATH=. python3 tests/contract/test_legacy_ratchet.py --write
"""
from __future__ import annotations

import ast
from collections import Counter
from contextlib import contextmanager
import fnmatch
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tokenize

import pytest

REPO = Path(__file__).resolve().parents[2]
RECORD = Path(__file__).with_name("legacy_ratchet.json")
REQUIRED_WORDS = (
    "soma", "cell", "genome", "enzyme", "wall", "membrane", "vacuole", "organ", "organelle",
    "telomere", "chloroplast", "plasmodesmata", "immune", "phylogeny", "mitosis", "apoptosis",
    "spore", "mycelium", "thorn", "bedrock", "mulch", "nucleus", "cytoplasm", "ribosome",
    "symbiosis", "germline", "phenotype", "genotype", "organism", "metabolism", "homeostasis",
)
ZERO_ROWS = (REQUIRED_WORDS[0] + "_imports", REQUIRED_WORDS[0] + "_classes", REQUIRED_WORDS[8] + "_type_literals")
SNAPSHOT_ROW = "contract_snapshots"
_PARTS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+")





# Phrase rules are location independent and pinned here; the record may only shrink them.
DEFAULT_ENGLISH_PATTERNS = frozenset({
    rf"(?i:{REQUIRED_WORDS[4]}[ _-]?(?:clock|time))",
    rf"(?i:{REQUIRED_WORDS[4]}[ _-]+of[ _-]+(?:text|prose))",
    "CLAUDE_CODE_USE_" + REQUIRED_WORDS[19].upper(),
    rf"(?i:(?:table|str|rendered|json|tsv)[ _-]+{REQUIRED_WORDS[1]}s?)",
    rf"(?i:(?:javascript|code[ _-]mode|code|execution|exec)[ _-]+{REQUIRED_WORDS[1]}s?)",
    rf"(?i:known[ _-]+{REQUIRED_WORDS[1]}[ _-]+shapes?)",
})
EXEMPT_FILE_KEYS = frozenset({
    'docs/hierarchy-dogfood.md',
    'tests/contract/legacy_ratchet.json',
    'tests/contract/public_names_4_3_3.json',
})
DEFERRED_COUNTS = {
    '.aegis/rules/boundaries/boundary-' + REQUIRED_WORDS[3] + 's.md': (0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    '.aegis/rules/contracts/contract-integrity-index-canonical-form.md': (0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    '.gitignore': (19, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'MANIFEST.in': (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'NOTICE': (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'aegis_cli/cli.py': (7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'aegis_cli/migrate.py': (4, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'aegis_cli/commands_table.py': (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'aegis_core/rules.py': (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'aegis_core/verification/import_guard.py': (0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'aegis_core/workspace/layout.py': (3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'docs/reference.md': (3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'tests/conftest.py': (3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'tests/contract/cli_tree.json': (3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'tests/unit/cli/test_hook_run.py': (2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'tests/unit/core/test_packs.py': (0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'tests/unit/core/test_supercell_' + REQUIRED_WORDS[1] + 's.py': (0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'tests/unit/core/test_v3_zero_legacy_invariants.py': (2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'tests/unit/mcp/test_mcp_argument_values.py': (0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'tests/unit/cli/test_cli_removed_commands.py': (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'aegis_core/ast/detect.py': (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'aegis_core/metrics.py': (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'aegis_core/verification/checkpoint_checks.py': (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    'aegis_core/verification/call_graph.py': (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
}
ORDINARY_ENTRY_KEYS = frozenset({
    '05bee4e181f5978dcd3c5360cf6a6968a5c225b370e7d13cc9399ad54d6d2d93',
    '09af018d486302ef9ce9f48d54ecb2ce786215680459a819cff29569a512bd3c',
    '0a99c26732ae0a1b3e594c6120b8ba6c39ee364d02cf535feeb2cefd2dd50612',
    '0bb90f21e64fbf5f27e604b75a8f7f0231bdece288045280973f10d9cba44a9b',
    '0c658d20d44058b6cc79504c45609629224241e7c12cea65bab95ccf3412f602',
    '0eb315b4ace7a0132dea7210755e2d285210cef5f6d0c759a6ef6c3dfbced003',
    '13b072dbd00946a109249c0ad8cefb8e8371d7fb3d4dce0d6758c5991113bbdd',
    '14492b204cd39086cde3d43f09bcd330c97f7e8037dc61b58960b365d53967dd',
    '162dfb9d460ce4d0a0cbeb7ab9a9eff400446dd21621f469838db7390a10e23b',
    '1709a6db7b7ee052f0e3ecbba716344f9569dab165cb6ac2c0a6c3209e88c6e4',
    '178ee309bfe92a52792e6e02389a3607c17fb8166f85e7773e96663a90bd0e6c',
    '1a10e581938fa55326acbcd35802de4721ea8a758bdab868613878056a6373f0',
    '1ba7def537ecdcd990f2b4130f6847d9e9ffa326ed1dcc6709d78b2edee66134',
    '1c47467534dac00923ead3b416e5085960058440dc2fbede9dc5fb078f008f9b',
    '226c042cf8b34358f12094257a3a85234fdac39e43f102198dc13266bb78f647',
    '22a70fe5f9565fa148bcfd052e8fe548f23fd402ff1afde2fa0512fa598bcf45',
    '28f6249d8dead08538e7da8a1496c33006dcb9ec44bbecbe3d8ffece9601b9f2',
    '29ddb2e195d1c0e423bd48e1f81c6b86996aa55d81ff359c168829096fafeeb6',
    '2a3b48e4e5034c27f6a66b426007b6fef4c3aab6a1cc86d71cd326a235ce25a0',
    '2ce2d47c8270fb2d36ec9663b7417360f4b3b6a3782d8c3b27c5f109be8a5601',
    '2f7694611c5ec1de5a1e66b3b460875fc2545c83dd700a5d66dff9644867b2b4',
    '315b0a45abf710987dbfae8690912d8abe7256227805e1d46df93237e8e018ac',
    '326d03dcf4a08db433f8a67fa66667446ec9f3fe16a1ff38628a04df80b10caf',
    '33746d5bc67eb295eaf2055bdb9c8fd4a4dfe8e06bb822128af4bdc9dd0b8447',
    '34f268053d481ce3ea53ae0275140ac3cfa591bf741dd622aaa9b449d95196c9',
    '3e1b226f0edccfdcd2d543afab1b5a548d8b6eb394413c8371e6e27d7191f765',
    '409bf89d24b7fb397498665c5b6ab7e5439bc73d697ea30507f199bb3463476f',
    '415f101c217a5443710b7d5f5867ba6c9f47cc8455174b07090c09f12758e267',
    '422ca353a91a286ab9420f5daf6c9f7cf6ad2bd44efb5dca6f0025b2fdb9cab4',
    '4586f0e748d6db8eaeaf1e3b465f5c3d7d0ea86b4341a28350810836e542fbff',
    '48643b8f97143533526290927880818145a9a518f1d966ba301f0b3bb3b3a0fc',
    '488cfa19233f8d0bec1b6c52fb096e29e75610e563a8c3a54679a727fef75545',
    '50ca722f41a88c389575bbe0afca9a9b8d962add8c63ffc79aef86973bbada5c',
    '534c887a90526462a2cdf1fa2dfd7983bea5a8b2e32da3e6408974398a507339',
    '540fd77e2db6db4daefd45bcd989f8229f2f5901d13045701a2cf1f5ba4d4142',
    '57360b9a909223ea5b1708508815e79906edada1190e1fd4dc86fabadecb4a87',
    '5a425c2c9c1e2f4354c51ca82a6f99df47f258a7b49da6e20d33fc45bf65ca4c',
    '6109fc86457f06f39031119e455d75ca287889687b6e656cf9230579b739bfce',
    '652716cf2d0a50138185bab4fcec5b6d39d53522c588e19e6b5ef91b67c3bd49',
    '6e83c546cee059b8e8f5c359010f8a2bd143e31e8889db811537f2459c8c22d7',
    '71778f7bd98f5fe9257d29937297391d198bfb9c5788b216fd668dc46394549d',
    '74b50e566d7e871df6ba92e2065cefa85e6396a59f0d8cacd1081edfb296a587',
    '7593795693244dc95152ae3a77778486055fbf52f377532e2d0c88bff23f08b7',
    '7ade0ca0087bf6cc8f7d46ea451dc7e484c3154c9af1f28c4fabcc5240ad9934',
    '7c1bf2f08b27dc7a7c64eae9ab3156153c62e2f9a15daf548dcd1558efbdf92f',
    '7c543097576febfaa0170fd8ef87b88bdbfd5478a85d9f91db10b8e17f1f0b05',
    '7e077f6982966da47c8e2214667b45981418dbb0386bbb908e38a8d4bbafe8c5',
    '7f410396f932d29d45fd6a10f93beeddebe38dc3b9bb5981e0db98b914eaef38',
    '83a1572a0aeb0c7d2203fdd9e47e02e5be19c56543e2d78e6fdc9209b3a29bad',
    '84ee6701b66e8473149ae55572e0f294cb3468ba6679d4d65753b7e0506bd308',
    '8c70312258b7ef18ec90025fb28509a04b54024cf2bac302a6f4216cf7d4e84c',
    '8e8d1f9022ee51edef3a098a2ad3dc75cfb1c4f32cfc94ac1835eefc4e591765',
    '8f47d3a2cd6d4675c17d0c710bf1ae7f42b9f7a62a9c6b57d412549506ed59d5',
    '8fd309e0ae368d9434f991218499ec0d81f8201b8b6fef8d803a0917ebbd18b1',
    '9156906c21b6d1b7dd91caf7423116c359c5df82b0b5e27ab09b48d01bc244a2',
    '92f3ef7f1d88223fa57354fabb4a18842ac4728b5a5ef3ad253149c826fbf4a5',
    '948eda1ad90ee6a9aec6c17e22da53515b70626e65139858d5f4a2f6ee1a207e',
    '96304aaa4a0a4de5da536b960c6318f44a25904091d55bc6d070eda15b265b30',
    '98af5e7069b04af0122655981db926e122e1655c4d704ab76134fca3e83bfaf0',
    '98c2336b34f6a96ecbfed25a2da9e6f679334df021333b6808d125377c2ff74f',
    '9ed6d76ea4ce738dfa64f64982ff0420168ea80602ae150cdec323b442716313',
    '9f69f898b6c354b19a6e7de6923e18f9c35f2e395faa2646cba50a60fc768ab0',
    'a2d70f6dcb445b9e3df3f164a5ce899545d5465617de3902837c5af6c0665005',
    'a95cc65b11f322ee7b9232295d0d50f1642c43387a32b88bd418fddd46643d6e',
    'a991fe033153f71d80210f69ecb5c873ab3789e90ad6ff6d4c8acbfa24f1bf41',
    'aab82d1b157b1f05be1b641fb55f1b4a6080bc6a22f758b1ee3fb03d54af8f21',
    'ab9f009c405e5a6b307558ddc79cbbf008d2e95e7cbf64c54aa7804db37a5cdb',
    'b22494961696d4bfc386d7949a3b987b8195087ba6fcd2252dd30c2b2883ca2b',
    'b53809bef3a1669f2399aaec37fd3bd5198f86b2ffad2e2ad2c6d3abd3c62ac6',
    'bae276ea84d39fece89b4de7dfdac7b5ff87e5fd124744e80f60cb1f10301a02',
    'be0f5caa3a2757e3d061a3f9332012019d2aec39d0b023810c18fe63b68f4ae5',
    'bec8db55fd20b3f8e0b24df81df7c4ff6bf2f450048a0b7b4dd788a41350c3fe',
    'beef40bd34645e9cb827affe95625eaec5ed3737372102039c0f2d4b2715375c',
    'c36c6d99e32a1e433d5f8d644972579f8d0b1d739cb387d9ef04469ac256d19a',
    'c8521106aa5e0ac5d1479c4e48e2a03ebad7207820de6d0688066798f0171812',
    'c8698409f36303c673e3cca41113727c5e98bd6581f66ea9da951fa66e3a6f04',
    'c904182fa76fc59ce8846593715a33b5af712fa85f3b55948ce23aaf2572dd0a',
    'c94fe7f9f561435f32f1c98354223102251a6d9b1fd27933e312ad03422dcbe6',
    'cdbc6b57dde8aeb54d54a4cbea7dce883f282206861aec75091a631c13ab71dc',
    'ce3dc0aa68804d34242eac77939f2b3c6096e09de764fd2d9aef6158f7d837f7',
    'd7549fc1cb2d36d4a6d0bb7c39c1d23d97a6217b2c55064091acb0b91e765472',
    'd7f521f18987a5054601af021ba5b8e397a2fc75ecfc50ea1b11189b1ecd03d4',
    'd929b337a68dec74adef56e08e99ad0d83a0eba0e87e8795d2fa2a3af14fff53',
    'dd017cf622e7db45b715ef1a96a78ce2bf45de4b90d2d467baf024bd0620e935',
    'de602bdc03cb6d04b2d9cf1b8875f4dbb2e0fb5ae752de48b9db54c4d309d49d',
    'dedcb2d71ffd171a19ded842c099b7313917e7481392a43cbb74cdf40f4b01bb',
    'e218d260b1573f09b09330347bb1b42599bb1abe57d5149eb071b8a2cf7c7ca5',
    'e352975bf1436c34ce5c293e81e441bf9d9e71565d1809749a73ccb4f1af9829',
    'e4cd9ba73d21ab5c3996afa0b801ede9c5fbe344ed62256aadf771471249dc78',
    'e7786b626ae08170be02f23a8ec56a77e90884b055138a51cfe9fe970f6842c1',
    'e961a2e4abb14da8e6b11c5f1d1e52269bb434a418963af9f600d4e615fbe76d',
    'f012e59d9230077e13374263b666e7c34eeeaf08a9f68156d47d1f2ac2ec3fc4',
    'f01a83b0367e38cbd5618e55162d7b2ad391e2c4c432f149c9adff8adff4d85d',
    'f1c1270aab1c608cbf9af90acdfba9173b759bf7bf980a123acfa7423f0f7c28',
    'f45543bf71dcf592dfad919a0508105645d6bf02f1c9c49052b93ac357b271ea',
    'f5ebd86572053d9d94bd9fb6ee68ca5765fbaa18009a21ac8e94cd961a7702e9',
    'f5ff610c9b2a4e1c501ef281aab6ece6fdf149807c9d2c69a556dd15705bdea0',
    'f6d797f9da832da3bb42835525b6482f2909035f2789b87884362e3ffddc1bfb',
    'f77dc6d787213951c6e73ae632688336d0ef48e308ad8b97c153e2d3e01cb8dd',
    'f8e22b8823ffd10e950624369a8a2ed335adf26b6164875a6135bb658450e919',
    'fd1dc8e5927b9c8a85ab7c7911e9be70dd01ce95b957f1fa8310a82277aa3bf8',
    'fe20657b1f1ea826ebad074c0737276f26985d9192ab8bd1c815f95732e2a39c',
    'ffa4fbe9975b6fb60c1b327762730c516ba5109dc9c4567706d5f7775363a484',
})
DOCUMENTED_REMOVAL_KEYS = frozenset({
    '1a5beee1fdf0b00496c8e0fd3e0197d6d49d83b4702d6d6c7472a6e520f4ef75',
    '4ffe366a5f4c510279f93f687887e10db29290f52e86dd672c95f557a5c83ae0',
    '713681de1ff6b2732c47dc8f2aefb04fba618c9b08ea6f704129eed54bb796ed',
    'a8dab479bf2a2f7d9dab291456ff5de03118dbe7a15e05b8e7c00b06fc9b922b',
    '17aa8cfe3fcb5f1907496c6971c389b0946bede26f52ed1c1f15e2081140f871',
    'b5599413b222c6c570197db50acf4ac4bcdd90bbc918a90340ffef4d0e688802',
    '6abc808f788718304b4b01b89879a8bb15612a74c1c15f43491560cc10e68f29',
    '9a487dd525741d9695be069a2b2b34e3e9c8578b00fad133098688bcd6299baf',
    '9b32844ac55323953b7c66d92e51dc61bb9f8cde0820daf27852d3982623fc59',
})
RELEASE_HEADING_KEYS = frozenset({
    '4568711dff3254c9cf7a6d64239b60f2c17b635a23392b2b3067ad1d382b1ebd',
    '2b6df90926bbc01023998c7d31d4e66b926d77e997085317418de94cda46e47b',
    '51fb84637e777346b4dac569ec87603c05951dd034b748421a4d309342d84ec7',
    'addb8b2db2602da78fca1b6fb97db72ff9dd1a37dc2184faccd1d3fd0da78164',
    '31e7781675c4bf8fc5b5637e62a7e294f2009983f8787fc0f24a086c80cb55f3',
    '29e7aa327fc4a18983cacb61f7b644df3eeff5862012d84ca1e56c6c956db3b5',
    '6d48ac86f1661adcf2b4cecd74808b987fc4fbdaff3b9b31b381edee94f2e142',
    'cd443990fdc75c79f627e6accecd4b13b24d0fc3d7fe3c2a110761acc23c98e3',
    'ee133b50af9f288077e03b9faa50c2bf83c84d470e15455f8ff7394d4f0f8246',
    '9a0ae8613e9874e86a17d03db0e20805c0e956e1291a8c24e4730d22776943b0',
    '4deff91536d27d7df4c25325dba584970a09500a23a2ed1ff288f5b9484f9a60',
    '6a564bf266e9fcf0f155dbc1d8d10f5dc3deb1716423d749db2f1fdc4fe39052',
    'eaf608689b33dec46328da4b816be5cd599d490a700ddbb89e3fd65ba7ab2afa',
    '38b33fda32d83445f6261a012d055f780c6ccc20b6560d79ff1d7a24257075b2',
    'b3fcb212dfe7ce87208cb3ea9ef5cfdabd5364a7e7c4a9e71118fafec68d936b',
    'af39f02887e52f7e4c2cc913b9589c5f10cc38885c46b87d6ba3662a13f93938',
    'b0fad5ca918f7666a9fa53a5c742bfc979db85bb0bb6e131f7a2eac443dff327',
    '8d389f7c9a1bb553448a22e9ec29f6506b9452fdd64938bf7da477842c14fa75',
    'd3f0c33229116f5011ffda0b1a77e88005883bc9733977b472b744167fa1ba12',
    '73b07c2ce90372294449ccc78a78a0c64847749bcd380b4f5c5bbedb4fdd60d2',
    'b5f97224ada943789f729cf3d619b53bf4c5c2e1399be74ab4d16b5c134415c8',
    '6edc8fb16f3307598eeb5eb5f2d574875c537e28303e34065794b1392d88e2c7',
    '31acb5bc8ade149669addc86d64dd644df470fdf3edf451f1692286616523e33',
    '973921d1ca3a869dff45f43b2e396d1699587d37ef09793f6d666c61d9894ba6',
    '3544922a8ceb9d39c400e40c90a75b064b51e83e0fbe66efc414706d3c1aef15',
    '54f3db9dde49fcafd48e7bf844b559c2b485828451dc161c8c54d5cae58f3255',
})

HISTORICAL_RECORD_IDS = frozenset({
    'DEBRIEF-001',
    'DEBRIEF-002',
    'DEBRIEF-003',
    'DEBRIEF-004',
    'DEBRIEF-005',
    'DEBRIEF-006',
    'DEBRIEF-007',
    'DEBRIEF-008',
})


def _filtered_counts(texts, words, patterns):
    for pattern in sorted(patterns):
        texts = [re.sub(pattern, " ", text) for text in texts]
    return _word_counts(texts, words)


def _ordinary_key(entry):
    identity = {key: entry[key] for key in ("file", "text", "occurrence", "counts")}
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def _mask_history(source, rel, history):
    lines = source.split("\n")
    for entry in history:
        if entry["file"] != rel:
            continue
        if "release_headings" in entry:
            released = False
            for index, line in enumerate(lines):
                if line.startswith("## "):
                    released = line in entry["release_headings"]
                if released:
                    lines[index] = ""
        elif "record_ids" in entry:
            remaining = Counter(entry["record_ids"])
            for index, line in enumerate(lines):
                if not line.strip():
                    continue
                record = json.loads(line)
                key = record.get("id") if isinstance(record, dict) else None
                if remaining[key]:
                    remaining[key] -= 1
                    lines[index] = ""
        elif "lines" in entry:
            remaining = Counter(entry["lines"])
            for index, line in enumerate(lines):
                if remaining[line]:
                    remaining[line] -= 1
                    lines[index] = ""
        else:
            start = lines.index(entry["start"])
            end = lines.index(entry["end"], start + 1)
            lines[start:end] = [""] * (end - start)
    return "\n".join(lines)


def _regular_bytes(path, before):
    """Validate and read one opened object, including platforms without no-follow."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode)
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise ValueError("cannot read listed text file")
        # Retain ownership even if fdopen itself raises.
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(fd)


def _tracked_text(path, root, tracked=True, expected_type=None):
    """One read boundary for both counters, including every post-listing touch."""
    import codecs

    try:
        before = path.lstat()
        mode = before.st_mode
        if expected_type is not None and stat.S_IFMT(mode) != expected_type:
            raise ValueError("cannot read listed text file")
        link = stat.S_ISLNK(mode)
        if not link and not stat.S_ISREG(mode):
            if tracked and expected_type != stat.S_IFDIR:
                raise ValueError("cannot read listed text file")
            return None
        raw = os.readlink(path) if link else _regular_bytes(path, before)
    except (FileNotFoundError, NotADirectoryError):
        if not tracked:
            return None
        raise ValueError("cannot read listed text file") from None
    except OSError:
        raise ValueError("cannot read listed text file") from None
    if any(part.startswith(("aegis-mutant-", "aegis-mutants-")) for part in path.relative_to(root).parts):
        raise ValueError("mutation scratch present in repository")
    if link:
        return raw, True
    encoding = "utf-8-sig"
    if raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        encoding = "utf-32"
    elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = "utf-16"
    try:
        source = raw.decode(encoding)
    except UnicodeDecodeError:
        raise ValueError(f"cannot decode tracked text file: {path.relative_to(root).as_posix()}") from None
    if "\x00" in source:
        raise ValueError(f"cannot decode tracked text file: {path.relative_to(root).as_posix()}")
    return source.replace("\r\n", "\n").replace("\r", "\n"), False


def file_counts(path, root, words, ordinary=(), history=(), patterns=None, *, content=None):
    rel = path.relative_to(root).as_posix()
    patterns = DEFAULT_ENGLISH_PATTERNS if patterns is None else patterns
    content = _tracked_text(path, root) if content is None else content
    if content is None:
        return dict.fromkeys(words, 0)
    source, link = content
    if link:
        return _filtered_counts([rel, source], words, patterns)
    if rel == "tests/contract/test_legacy_ratchet.py":
        source = _without_word_list(source)
    source = _mask_history(source, rel, history)
    lines = source.split("\n")
    texts = _python_texts(source) if path.suffix == ".py" else lines
    counts = _filtered_counts(texts, words, patterns)
    if path.suffix in (".json", ".jsonl"):
        values = [json.loads(source)] if path.suffix == ".json" else [json.loads(line) for line in lines if line.strip()]
        decoded = _filtered_counts([text for value in values for text in _json_texts(value)], words, patterns)
        counts = {word: max(counts[word], decoded[word]) for word in words}
    names = _filtered_counts([rel], words, patterns)
    counts = {word: counts[word] + names[word] for word in words}
    for entry in ordinary:
        if entry["file"] != rel or lines.count(entry["text"]) <= entry["occurrence"]:
            continue
        expected = {key: value for key, value in _filtered_counts([entry["text"]], REQUIRED_WORDS, patterns).items() if value}
        assert expected == entry["counts"], f"English exemption changed: {rel}"
        for word, count in expected.items():
            if word in counts:
                counts[word] -= count
                assert counts[word] >= 0, f"English exemption exceeds decoded count: {rel}"
    return counts


def _data():
    return json.loads(RECORD.read_text(encoding="utf-8"))


def check_exclusion_keys(data):
    assert set(data["exempt_files"]) <= EXEMPT_FILE_KEYS, "whole-file exemptions grew"
    assert set(data["ordinary_patterns"]) <= DEFAULT_ENGLISH_PATTERNS, "English patterns grew"
    ordinary = [_ordinary_key(entry) for entry in data["ordinary_english"]]
    assert len(ordinary) == len(set(ordinary)) and set(ordinary) <= ORDINARY_ENTRY_KEYS, "English entries grew"
    assert set(data["deferred"]) <= set(DEFERRED_COUNTS), "deferred keys grew"
    for rel, entry in data["deferred"].items():
        assert set(entry["counts"]) == set(REQUIRED_WORDS)
        assert all(entry["counts"][word] <= maximum for word, maximum in zip(REQUIRED_WORDS, DEFERRED_COUNTS[rel])), f"deferred counts grew: {rel}"
    files = [entry["file"] for entry in data["historical_sections"]]
    assert len(files) == len(set(files))
    assert set(files) <= {"CHANGELOG.md", "docs/why-aegis.md", "governance/debrief_queue.jsonl"}
    for entry in data["historical_sections"]:
        assert set(entry.get("record_ids", ())) <= HISTORICAL_RECORD_IDS, "historical ids grew"
        if entry["file"] == "docs/why-aegis.md":
            assert set(entry) <= {"file", "start", "end", "reason"}
            assert (entry["start"], entry["end"]) == ("## Appendix B: Re-deriving the numbers", "## Planned, not shipped")
        elif entry["file"] == "CHANGELOG.md":
            assert set(entry) <= {"file", "release_headings", "reason"}
            assert {hashlib.sha256(heading.encode()).hexdigest() for heading in entry["release_headings"]} <= RELEASE_HEADING_KEYS, "release headings grew"
            assert len(entry["release_headings"]) == len(set(entry["release_headings"]))
        else:
            assert set(entry) <= {"file", "record_ids", "reason"}
            assert len(entry["record_ids"]) == len(set(entry["record_ids"]))
    files = [entry["file"] for entry in data["documented_removals"]]
    assert len(files) == len(set(files)) and set(files) <= {"CHANGELOG.md"}
    assert all(set(entry) <= {"file", "lines", "reason"} and len(entry["lines"]) == len(set(entry["lines"])) for entry in data["documented_removals"])
    assert {hashlib.sha256(line.encode()).hexdigest() for entry in data["documented_removals"] for line in entry["lines"]} <= DOCUMENTED_REMOVAL_KEYS, "documented removals grew"



def word_parts(text):
    # Decode language literals in their parser; a literal path separator never
    # consumes the first letter of the next component.
    text = text.replace("\\", " ")
    parts = [part.lower() for part in _PARTS.findall(text)]
    brand = REQUIRED_WORDS[0]
    return [piece for part in parts for piece in
            ((brand, part[len(brand):]) if part.startswith(brand) and part != brand else (part,))]


def _word_counts(texts, words):
    parts = Counter(part for text in texts for part in word_parts(text))
    return {word: parts[word] + parts[word + "s"] for word in words}


def repository_files(root):
    """Git's tracked and nonignored new files, including hidden configuration.

    Git's deleted-file view excludes pre-listing deletions. Preserve membership
    thereafter without a racy stat/filter pass; tracked disappearance refuses.
    """
    listed = {}
    deleted = subprocess.run(
        ["git", "ls-files", "--deleted", "-z"], cwd=root, check=True, stdout=subprocess.PIPE,
    )
    absent = set(deleted.stdout.decode("utf-8").split("\0"))
    others = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=root, check=True, stdout=subprocess.PIPE,
    )
    listed.update({root / name: (False, None) for name in others.stdout.decode("utf-8").split("\0") if name})
    cached = subprocess.run(
        ["git", "ls-files", "--cached", "--stage", "-z"], cwd=root, check=True, stdout=subprocess.PIPE,
    )
    types = {"100644": stat.S_IFREG, "100755": stat.S_IFREG, "120000": stat.S_IFLNK, "160000": stat.S_IFDIR}
    for entry in cached.stdout.decode("utf-8").split("\0"):
        if not entry:
            continue
        try:
            metadata, name = entry.split("\t", 1)
            mode, _, stage = metadata.split()
            expected_type = types[mode]
            if stage != "0":
                raise ValueError
        except (ValueError, KeyError):
            raise ValueError("cannot list repository files") from None
        if name not in absent:
            listed[root / name] = (True, expected_type)
    return dict(sorted(listed.items()))


def _without_word_list(text):
    lines = text.splitlines(keepends=True)
    node = next(n for n in ast.parse(text).body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "REQUIRED_WORDS" for t in n.targets))
    lines[node.lineno - 1:node.end_lineno] = ["\n"] * (node.end_lineno - node.lineno + 1)
    return "".join(lines)


def _python_texts(source):
    # Invalid bytes remain visible to the text counter without preventing AST
    # parsing when they appear in a comment or string.
    source = source.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    class FoldText(ast.NodeTransformer):
        def visit_BinOp(self, node):
            node = self.generic_visit(node)
            if (isinstance(node.op, ast.Add) and isinstance(node.left, ast.Constant)
                    and isinstance(node.right, ast.Constant) and isinstance(node.left.value, (str, bytes))
                    and type(node.left.value) is type(node.right.value)):
                return ast.copy_location(ast.Constant(value=node.left.value + node.right.value), node)
            return node

    tree = FoldText().visit(ast.parse(source))
    texts = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            texts.append(node.value if isinstance(node.value, str) else node.value.decode("utf-8", "surrogateescape"))
        elif isinstance(node, ast.Name):
            texts.append(node.id)
        elif isinstance(node, ast.Attribute):
            texts.append(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            texts.append(node.name)
        elif isinstance(node, ast.arg):
            texts.append(node.arg)
        elif isinstance(node, ast.keyword) and node.arg:
            texts.append(node.arg)
        elif isinstance(node, ast.alias):
            texts.extend([node.name, node.asname or ""])
        elif isinstance(node, ast.ImportFrom):
            texts.append(node.module or "")
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            texts.extend(node.names)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            texts.append(node.name)
    texts.extend(token.string for token in tokenize.generate_tokens(io.StringIO(source).readline)
                 if token.type == tokenize.COMMENT)
    return texts


def _json_texts(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for key, item in value.items() for text in [key, *_json_texts(item)]]
    if isinstance(value, list):
        return [text for item in value for text in _json_texts(item)]
    return []


def tree_counts(data=None, root=None):
    data = _data() if data is None else data
    root = REPO if root is None else root
    total = dict.fromkeys(REQUIRED_WORDS, 0)
    deferred = {rel: dict.fromkeys(REQUIRED_WORDS, 0) for rel in data.get("deferred", {})}
    files = {}
    all_paths = repository_files(root)
    contents = {}
    for path, (tracked, expected_type) in all_paths.items():
        content = _tracked_text(path, root, tracked, expected_type)
        if content is not None:
            contents[path] = content
    for path, content in contents.items():
        rel = path.relative_to(root).as_posix()
        if rel in data.get("exempt_files", {}) or any(fnmatch.fnmatchcase(rel, p) for p in data.get("exempt_patterns", {})):
            continue
        counts = file_counts(path, root, REQUIRED_WORDS, data.get("ordinary_english", ()),
                             [*data.get("historical_sections", ()), *data.get("documented_removals", ())],
                             data.get("ordinary_patterns", DEFAULT_ENGLISH_PATTERNS), content=content)
        if rel in data.get("deferred", {}):
            deferred[rel] = counts
        else:
            files[rel] = counts
            for word, count in counts.items():
                total[word] += count
    total.update(dict.fromkeys(ZERO_ROWS, 0))
    total[SNAPSHOT_ROW] = sum(sum(counts.values()) for rel, counts in files.items()
                              if rel in ("tests/contract/cli_tree.json", "tests/contract/mcp_tools.json"))
    for path, (source, link) in contents.items():
        if path.suffix != ".py" or link:
            continue
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                total[ZERO_ROWS[0]] += sum(name.startswith(REQUIRED_WORDS[0] + "_") for name in names)
            if isinstance(node, ast.ClassDef):
                total[ZERO_ROWS[1]] += node.name.startswith(REQUIRED_WORDS[0].capitalize())
            elif isinstance(node, ast.Assign):
                total[ZERO_ROWS[1]] += sum(isinstance(t, ast.Name) and t.id.startswith(REQUIRED_WORDS[0].capitalize())
                                         for t in node.targets)
    total[ZERO_ROWS[2]] = sum(total[word] for word in (REQUIRED_WORDS[6], REQUIRED_WORDS[10], REQUIRED_WORDS[11]))
    return total, deferred, files


def current_counts(words):
    counts, _, _ = tree_counts()
    return {word: counts[word] for word in words}


def lowered(record, current):
    rose = {row: (record.get(row, 0), value) for row, value in current.items() if value > record.get(row, 0)}
    if rose:
        raise ValueError(f"refusing to raise records: {rose}")
    return {row: current.get(row, 0) for row in record}



def test_evidence_exemptions_record_paths_and_reasons():
    data = _data()
    check_exclusion_keys(data)
    assert all(reason and (REPO / rel).is_file() for rel, reason in data["exempt_files"].items())
    assert "HISTORY_DIGESTS" not in globals()
    assert all("line" not in entry and entry["occurrence"] >= 0 for entry in data["ordinary_english"])


@pytest.mark.parametrize("category", ["exempt_files", "deferred"])
def test_exclusion_keys_can_only_shrink(category):
    data = _data()
    data[category] = {}
    check_exclusion_keys(data)
    data[category]["new-unreviewed-file.txt"] = {}
    with pytest.raises(AssertionError, match="grew"):
        check_exclusion_keys(data)


def test_exemption_rules_and_deferred_counts_cannot_grow_in_json():
    for mutation in ("pattern", "entry", "count"):
        data = _data()
        if mutation == "pattern":
            data["ordinary_patterns"].append("new phrase")
        elif mutation == "entry":
            data["ordinary_english"].append(dict(file="new.py", text=REQUIRED_WORDS[0], occurrence=0, counts={REQUIRED_WORDS[0]: 1}, reason="Unreviewed."))
        else:
            rel = next(iter(data["deferred"]))
            data["deferred"][rel]["counts"][REQUIRED_WORDS[0]] += 1
        with pytest.raises(AssertionError, match="grew"):
            check_exclusion_keys(data)


@pytest.mark.parametrize("mutation", ["section", "duplicate-history", "duplicate-note", "duplicate-English"])
def test_exemption_scopes_and_multiplicity_cannot_grow(mutation):
    data = _data()
    if mutation == "section":
        data["historical_sections"][0]["start"] = "# Whole document"
    elif mutation == "duplicate-history":
        data["historical_sections"].append(data["historical_sections"][-1])
    elif mutation == "duplicate-note":
        data["documented_removals"].append(data["documented_removals"][0])
    else:
        data["ordinary_english"].append(data["ordinary_english"][0])
    with pytest.raises(AssertionError):
        check_exclusion_keys(data)


def test_unrelated_breaking_lines_are_counted_without_an_exemption(tmp_path):
    data = _data()
    path = tmp_path / "CHANGELOG.md"
    source = (REPO / path.name).read_text(encoding="utf-8")
    source = source.replace("## [Unreleased]\n", "## [Unreleased]\n\n- Breaking: unrelated.api was removed.\n", 1)
    path.write_text(source, encoding="utf-8")
    assert not any(file_counts(path, tmp_path, REQUIRED_WORDS, data["ordinary_english"], [*data["historical_sections"], *data["documented_removals"]], data["ordinary_patterns"]).values())


def test_documented_removals_contain_required_words_only():
    data = _data()
    source = (REPO / "CHANGELOG.md").read_text(encoding="utf-8").split("## [4.5.0]", 1)[0]
    for entry in data["documented_removals"]:
        for line in entry["lines"]:
            assert line in source.splitlines() and line.startswith("- Breaking:")
            assert any(_word_counts([line], REQUIRED_WORDS).values())


def test_section_history_and_new_audit_ids(tmp_path):
    word = REQUIRED_WORDS[0]
    path = tmp_path / "notes.md"
    history = [dict(file=path.name, start="## History", end="## Current")]
    path.write_text("## History\n" + word + "\n" + word + "\n## Current\n")
    assert file_counts(path, tmp_path, (word,), history=history)[word] == 0
    path.write_text(path.read_text() + word)
    assert file_counts(path, tmp_path, (word,), history=history)[word] == 1
    path = tmp_path / "queue.jsonl"
    history = [dict(file=path.name, record_ids=["old"])]
    old = json.dumps(dict(id="old", text=word)) + "\n"
    path.write_text(old)
    assert file_counts(path, tmp_path, (word,), history=history)[word] == 0
    path.write_text(old + json.dumps(dict(id="new", text=word)) + "\n")
    assert file_counts(path, tmp_path, (word,), history=history)[word] == 1
    path.write_text(old + old)
    assert file_counts(path, tmp_path, (word,), history=history)[word] == 1


def test_exact_text_exemptions_do_not_cover_edited_lines(tmp_path):
    word = REQUIRED_WORDS[1]
    path = tmp_path / "notes.txt"
    text = "one " + word
    entry = dict(file=path.name, text=text, occurrence=0, counts={word: 1})
    path.write_text("\n" + text)
    assert file_counts(path, tmp_path, (word,), ordinary=[entry])[word] == 0
    path.write_text("\n" + text + " " + REQUIRED_WORDS[0])
    assert file_counts(path, tmp_path, REQUIRED_WORDS, ordinary=[entry])[REQUIRED_WORDS[0]] == 1



def test_the_record_keeps_every_required_row():
    data = _data()
    assert set(data["counts"]) == set((*REQUIRED_WORDS, *ZERO_ROWS, SNAPSHOT_ROW))
    assert all(value == 0 for value in data["counts"].values())
    assert "CHANGELOG.md" not in data["exempt_files"]
    assert "governance/debrief_queue.jsonl" not in data["exempt_files"]
    assert data["exempt_patterns"] == {"tests/fixtures/**": "Immutable fixture evidence; requires an owner successor pin."}
    assert all(entry["reason"] and entry["counts"] for entry in data["ordinary_english"])


@pytest.fixture
def external_scratch_root():
    import tempfile

    with tempfile.TemporaryDirectory(prefix="rf-external-scratch-") as root:
        yield Path(root)


@contextmanager
def _git_environment(cwd=None):
    names = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_CEILING_DIRECTORIES")
    saved = {name: os.environ.get(name) for name in names}
    previous_cwd = Path.cwd()
    try:
        for name in names[:3]:
            os.environ.pop(name, None)
        if cwd is not None:
            os.chdir(cwd)
        yield
    finally:
        if cwd is not None:
            os.chdir(previous_cwd)
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


_SCRATCH_INSIDE_DETAIL = "could not assess: mutation scratch root is not outside the checkout"
_INVALID_LAYOUT_DETAIL = (
    "could not assess: invalid explicit Git layout: "
    "GIT_DIR requires GIT_WORK_TREE; "
    "GIT_DIR, GIT_WORK_TREE and GIT_COMMON_DIR must name existing directories"
)
_BOUNDARY_DETAIL = (
    "could not assess: Git boundary could not be verified: "
    "confirm GIT_DIR and GIT_WORK_TREE describe one checkout"
)


def _unusable_layout_detail(layout: str) -> str:
    """A missing or non-directory component is an invalid layout; Git refusing it is not."""
    if layout == "unresolved" or "file-parent" in layout:
        return _INVALID_LAYOUT_DETAIL
    return _BOUNDARY_DETAIL


@pytest.mark.parametrize("suffix", [".py", ".rs"])
@pytest.mark.parametrize("inside", [False, True], ids=["outside", "inside"])
def test_mutation_scratch_stays_outside_checkout(tmp_path, monkeypatch, suffix, inside, external_scratch_root):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").mkdir()
    scratch = (checkout if inside else external_scratch_root) / "scratch"
    scratch.mkdir()
    target = checkout / "package" / ("target" + suffix)
    target.parent.mkdir()
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test = checkout / "test_target.py"
    test.write_text(
        (f"import sys\nsys.path.insert(0, {str(target.parent)!r})\nfrom target import add\n"
         "def test_add():\n    assert add(2, 3) == 5\n") if suffix == ".py" else
        "def test_ok():\n    assert True\n", encoding="utf-8",
    )
    real_tempfile = mutation_tester.tempfile
    created = []

    def temporary_directory(**kwargs):
        kwargs.setdefault("dir", str(scratch))
        directory = real_tempfile.TemporaryDirectory(**kwargs)
        created.append(Path(directory.name))
        return directory

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(scratch), TemporaryDirectory=temporary_directory,
    ))
    # The external driver is a real boundary; no mutation-stage internals are patched.
    from aegis_core.ast.schema import MutationPoint
    point = MutationPoint(line=2, col=0, original_op="+", replacement_op="-")
    runner = SimpleNamespace(parse_file=lambda _: SimpleNamespace(mutation_points=[point]))
    for _ in range(2):
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1, ast_runner=runner)
        if inside:
            assert result.verdict is False
            assert result.detail == "could not assess: mutation scratch root is not outside the checkout"
            assert result.lines == [-1]
        else:
            assert "survived" in result.detail, result.detail
            assert result.verdict is (suffix == ".py"), result.detail
    if inside:
        assert created == []
        return
    assert len(created) == 2
    assert all(checkout.resolve() not in directory.resolve().parents for directory in created)
    assert all(REPO not in directory.resolve().parents for directory in created)
    assert all(not directory.exists() for directory in created)


@pytest.mark.parametrize("kind", ["missing", "file", "invalid", "permission"])
def test_invalid_mutation_root_refuses_before_allocation(tmp_path, monkeypatch, kind):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    target = tmp_path / "target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test = tmp_path / "test_target.py"
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    candidate = tmp_path / "scratch"
    if kind == "file":
        candidate.write_text("regular file", encoding="utf-8")
    if kind == "invalid":
        candidate = "private\x00diagnostic"

    class RefusingPath(type(tmp_path)):
        def resolve(self, *args, **kwargs):
            if self == candidate and kind == "permission":
                raise PermissionError("private diagnostic")
            return super().resolve(*args, **kwargs)

    def forbidden_allocation(**kwargs):
        pytest.fail("invalid root reached scratch allocation")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.Path", RefusingPath)
    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=forbidden_allocation,
    ))
    for _ in range(2):
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
        assert result.verdict is False
        assert result.detail == (
            "could not assess: mutation scratch root is not usable: "
            "choose an existing, accessible directory outside the checkout"
        )
        assert result.lines == [-1]


@pytest.mark.parametrize("suffix", [".py", ".rs"])
@pytest.mark.parametrize("layout", ["root", "intermediate", "beside", "explicit"])
def test_target_checkout_scratch_refuses_independently_of_candidate(monkeypatch, suffix, layout):
    import tempfile
    from types import SimpleNamespace
    from aegis_core.ast.schema import MutationPoint
    from aegis_core.verification import mutation_tester

    with _git_environment(), tempfile.TemporaryDirectory(prefix="rf-root-boundary-") as directory:
        checkout = Path(directory) / "checkout"
        package = checkout / "src" / "package"
        package.mkdir(parents=True)
        if layout == "explicit":
            metadata = Path(directory) / "metadata.git"
            subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True)
            os.environ["GIT_DIR"] = str(metadata)
            os.environ["GIT_WORK_TREE"] = str(checkout)
            assert not (checkout / ".git").exists()
        else:
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
        assert REPO not in checkout.parents
        target = package / ("target" + suffix)
        target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        test = package / "test_target.py"
        test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        candidate = checkout / "scratch" if layout == "beside" else (
            checkout / "src" if layout == "intermediate" else checkout
        )
        candidate.mkdir(exist_ok=True)

        def forbidden_allocation(**kwargs):
            pytest.fail("target checkout reached scratch allocation")

        monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
            gettempdir=lambda: str(candidate), TemporaryDirectory=forbidden_allocation,
        ))
        point = MutationPoint(line=2, col=0, original_op="+", replacement_op="-")
        runner = SimpleNamespace(parse_file=lambda _: SimpleNamespace(mutation_points=[point]))
        for _ in range(2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1, ast_runner=runner)
            assert result.verdict is False
            assert result.detail == "could not assess: mutation scratch root is not outside the checkout"
            assert result.lines == [-1]


@pytest.mark.parametrize("inside", [False, True], ids=["sibling-control", "cwd-checkout"])
@pytest.mark.parametrize("boundary_owner", ["cwd", "tool"])
def test_cwd_and_tool_checkout_roots_are_scratch_boundaries(monkeypatch, inside, boundary_owner):
    import tempfile
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    with _git_environment(), tempfile.TemporaryDirectory(prefix="rf-cwd-boundary-") as directory:
        outer = Path(directory)
        checkout, target_checkout = outer / "cwd-checkout", outer / "target-checkout"
        subdir, package = checkout / "sub", target_checkout / "package"
        subdir.mkdir(parents=True)
        package.mkdir(parents=True)
        for repo in (checkout, target_checkout):
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
        os.environ["GIT_CEILING_DIRECTORIES"] = str(outer)
        target, test = package / "target.py", package / "test_target.py"
        target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        test.write_text(f"import sys\nsys.path.insert(0, {str(package)!r})\nfrom target import add\n"
                        "def test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
        candidate = (checkout if inside else outer) / "scratch"
        candidate.mkdir()
        real_tempfile = mutation_tester.tempfile
        real_module_file = Path(mutation_tester.__file__)
        installed_module = checkout / "installed" / "aegis_core" / "verification" / "mutation_tester.py"
        installed_module.parent.mkdir(parents=True)
        installed_module.write_text("# fixture module location\n", encoding="utf-8")
        created = []

        class CwdPath(type(Path())):
            @classmethod
            def cwd(cls):
                return cls(subdir) if boundary_owner == "cwd" else super().cwd()

            def resolve(self, *args, **kwargs):
                if boundary_owner == "tool" and self == real_module_file:
                    return type(self)(installed_module)
                return super().resolve(*args, **kwargs)

        def allocate(**kwargs):
            if inside:
                pytest.fail("cwd checkout reached scratch allocation")
            manager = real_tempfile.TemporaryDirectory(**kwargs)
            created.append(Path(manager.name))
            return manager

        monkeypatch.setattr("aegis_core.verification.mutation_tester.Path", CwdPath)
        monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
            gettempdir=lambda: str(candidate), TemporaryDirectory=allocate,
        ))
        for _ in range(2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
            if inside:
                assert result.verdict is False
                assert result.detail == "could not assess: mutation scratch root is not outside the checkout"
                assert result.lines == [-1]
            else:
                assert result.verdict is True, result.detail
        assert len(created) == (0 if inside else 2)
        assert all(not path.exists() for path in created)


def test_broken_git_marker_still_bounds_mutation_scratch(monkeypatch):
    import tempfile
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester
    from tests.conftest import symlink_or_skip

    with _git_environment(), tempfile.TemporaryDirectory(prefix="rf-broken-marker-") as directory:
        checkout = Path(directory) / "checkout"
        package = checkout / "package"
        package.mkdir(parents=True)
        symlink_or_skip("absent-metadata", checkout / ".git", target_is_directory=True)
        target, test = package / "target.py", package / "test_target.py"
        target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")

        def forbidden_allocation(**kwargs):
            pytest.fail("broken Git marker reached scratch allocation")

        monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
            gettempdir=lambda: str(checkout), TemporaryDirectory=forbidden_allocation,
        ))
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
        assert result.verdict is False
        assert result.detail == "could not assess: mutation scratch root is not outside the checkout"
        assert result.lines == [-1]


def test_mutation_root_symlink_into_checkout_is_refused(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester
    from tests.conftest import symlink_or_skip

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").mkdir()
    target = checkout / "target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test = checkout / "test_target.py"
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    alias = tmp_path / "outside-alias"
    symlink_or_skip(checkout, alias, target_is_directory=True)

    def forbidden_allocation(**kwargs):
        pytest.fail("symlink into checkout reached scratch allocation")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(alias), TemporaryDirectory=forbidden_allocation,
    ))
    result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
    assert result.verdict is False
    assert result.detail == "could not assess: mutation scratch root is not outside the checkout"
    assert result.lines == [-1]


@pytest.mark.parametrize("suffix", [".py", ".rs"])
@pytest.mark.parametrize("invoked_from", ["other-checkout", "target-checkout"])
@pytest.mark.parametrize("layout", ["relative", "absolute", "unresolved", "common-relative",
                                  "parent-relative", "parent-absolute", "pointer-relative",
                                  "pointer-absolute", "pointer-file-parent-relative",
                                  "pointer-file-parent-absolute", "pointer-invalid-relative",
                                  "pointer-invalid-absolute"])
@pytest.mark.parametrize("external", [False, True], ids=["checkout-scratch", "external-scratch"])
def test_explicit_layout_keeps_invocation_paths(
    tmp_path, monkeypatch, suffix, invoked_from, layout, external, external_scratch_root,
):
    from types import SimpleNamespace
    from aegis_core.ast.schema import MutationPoint
    from aegis_core.verification import mutation_tester

    checkout, other, metadata = tmp_path / "B", tmp_path / "A", tmp_path / "metadata.git"
    pointer = layout.startswith("pointer-")
    unusable = layout == "unresolved" or layout.startswith(("pointer-file-parent-", "pointer-invalid-"))
    package = checkout / "src" / "package"
    package.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(other)], check=True)
    command = ["git", "init", "-q", "--separate-git-dir", str(metadata), str(checkout)] if pointer else [
        "git", "init", "--bare", "-q", str(metadata),
    ]
    subprocess.run(command, check=True, timeout=30)
    target, test = package / ("target" + suffix), package / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text(
        (f"import sys\nsys.path.insert(0, {str(package)!r})\nfrom target import add\n"
         "def test_add():\n    assert add(2, 3) == 5\n") if suffix == ".py" else
        "def test_ok():\n    assert True\n", encoding="utf-8",
    )
    invocation = other if invoked_from == "other-checkout" else checkout

    real_tempfile = mutation_tester.tempfile
    allocated = []

    def allocate(**kwargs):
        if not external or unusable:
            pytest.fail("explicit checkout layout reached scratch allocation")
        manager = real_tempfile.TemporaryDirectory(**kwargs)
        allocated.append(Path(manager.name))
        return manager

    candidate = external_scratch_root / "scratch" if external or unusable else checkout
    candidate.mkdir(exist_ok=True)
    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=allocate,
    ))
    point = MutationPoint(line=2, col=0, original_op="+", replacement_op="-")
    runner = SimpleNamespace(parse_file=lambda _: SimpleNamespace(mutation_points=[point]))
    with _git_environment(invocation):
        os.environ["GIT_DIR"] = str(metadata) if layout in ("absolute", "common-relative", "parent-absolute") else "../metadata.git"
        os.environ["GIT_WORK_TREE"] = str(checkout) if layout in ("absolute", "common-relative", "parent-absolute") else "../B"
        if layout == "unresolved":
            os.environ["GIT_DIR"] = "../missing.git"
        if layout == "common-relative":
            os.environ["GIT_COMMON_DIR"] = "../metadata.git"
        if pointer:
            path = str(checkout / ".git")
            assert Path(path).is_file()
            if "invalid" in layout:
                Path(path).write_text("private diagnostic\n", encoding="utf-8")
            if "file-parent" in layout:
                path += "/../.git"
            os.environ["GIT_DIR"] = path if layout.endswith("absolute") else os.path.relpath(checkout, invocation) + path[len(str(checkout)):]
            native = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=invocation,
                                    capture_output=True, timeout=30)
            assert (native.returncode != 0) is unusable
        if layout.startswith("parent-"):
            os.environ["GIT_COMMON_DIR"] = os.environ["GIT_DIR"]
            for root in (metadata, checkout):
                (root / "existing").mkdir()
            for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"):
                os.environ[name] += "/existing/.."
        before = {name: os.environ.get(name) for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")}
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1, ast_runner=runner)
        if not external or unusable:
            assert result.verdict is False
            assert result.detail == (_unusable_layout_detail(layout) if unusable else _SCRATCH_INSIDE_DETAIL)
            assert "private diagnostic" not in result.detail
            assert result.lines == [-1]
            assert allocated == []
        else:
            assert "survived" in result.detail, result.detail
            assert result.verdict is (suffix == ".py"), result.detail
            assert len(allocated) == 1
            assert allocated[0].parent == candidate.resolve()
            assert not allocated[0].exists()
        assert {name: os.environ.get(name) for name in before} == before


@pytest.mark.parametrize("name", ["GIT_DIR", "GIT_COMMON_DIR"])
@pytest.mark.parametrize("shape", ["dots", "slashes", "trailing-dot", "parent"])
@pytest.mark.parametrize("long", [False, True], ids=["short", "long"])
@pytest.mark.parametrize("absolute", [False, True], ids=["relative", "absolute"])
def test_explicit_layout_preserves_native_path_spelling(
    monkeypatch, external_scratch_root, name, shape, long, absolute,
):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    checkout, other, metadata = (external_scratch_root / part for part in ("B", "A", "metadata.git"))
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(other)], check=True, timeout=30)
    subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True, timeout=30)
    (metadata / "existing").mkdir()
    target, test = checkout / "target.py", checkout / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text(f"import sys\nsys.path.insert(0, {str(checkout)!r})\nfrom target import add\n"
                    "def test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
    suffix = {"dots": "/./", "slashes": "//", "trailing-dot": "/.", "parent": "/existing/.."}[shape]
    value = (str(metadata) if absolute else os.path.relpath(metadata, other)) + suffix * (
        4800 // len(suffix) if long else 1
    )
    assert len(value) <= 65536
    scratch = external_scratch_root / "scratch"
    scratch.mkdir()
    real_tempfile, allocated = mutation_tester.tempfile, []
    native_accepts = False

    def allocate(**kwargs):
        assert native_accepts, "native-refused Git layout reached scratch allocation"
        manager = real_tempfile.TemporaryDirectory(**kwargs)
        allocated.append(Path(manager.name))
        return manager

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(scratch), TemporaryDirectory=allocate,
    ))
    with _git_environment(other):
        os.environ.update(GIT_DIR=str(metadata), GIT_WORK_TREE=str(checkout), GIT_COMMON_DIR=str(metadata))
        os.environ[name] = value
        before = {key: os.environ[key] for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")}
        native = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, timeout=30)
        native_accepts = native.returncode == 0
        for _ in range(1 if native_accepts else 2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
            if native_accepts:
                assert result.verdict is True, result.detail
                assert "survived" in result.detail
                assert len(allocated) == 1
                assert allocated[0].parent == scratch.resolve()
                assert not allocated[0].exists()
            else:
                assert result.verdict is False
                assert result.detail == _BOUNDARY_DETAIL
                assert os.environ[name] not in result.detail
                assert result.lines == [-1]
                assert allocated == []
            assert {key: os.environ[key] for key in before} == before


@pytest.mark.parametrize("pointer_parent", ["declared", "canonical"])
@pytest.mark.parametrize("absolute", [False, True], ids=["relative", "absolute"])
def test_git_pointer_file_symlink_preserves_declared_parent(
    monkeypatch, external_scratch_root, pointer_parent, absolute,
):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester
    from tests.conftest import symlink_or_skip

    checkout, other, metadata = (external_scratch_root / part for part in ("B", "A", "metadata.git"))
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(other)], check=True, timeout=30)
    subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True, timeout=30)
    pointer = external_scratch_root / "far" / "nested" / "gitfile"
    pointer.parent.mkdir(parents=True)
    relative = "../metadata.git" if pointer_parent == "declared" else "../../metadata.git"
    pointer.write_text("gitdir: " + relative + "\n", encoding="utf-8")
    alias = checkout / ".git"
    symlink_or_skip(pointer, alias)
    target, test = checkout / "target.py", checkout / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text(f"import sys\nsys.path.insert(0, {str(checkout)!r})\nfrom target import add\n"
                    "def test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
    scratch = external_scratch_root / "scratch"
    scratch.mkdir()
    real_tempfile, allocated = mutation_tester.tempfile, []
    native_accepts = False

    def allocate(**kwargs):
        assert native_accepts, "native-refused pointer layout reached scratch allocation"
        manager = real_tempfile.TemporaryDirectory(**kwargs)
        allocated.append(Path(manager.name))
        return manager

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(scratch), TemporaryDirectory=allocate,
    ))
    with _git_environment(other):
        os.environ["GIT_DIR"] = str(alias) if absolute else os.path.relpath(alias, other)
        os.environ["GIT_WORK_TREE"] = str(checkout)
        before = {key: os.environ[key] for key in ("GIT_DIR", "GIT_WORK_TREE")}
        native = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, timeout=30)
        native_accepts = native.returncode == 0
        for _ in range(1 if native_accepts else 2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
            if native_accepts:
                assert result.verdict is True, result.detail
                assert "survived" in result.detail
                assert len(allocated) == 1
                assert allocated[0].parent == scratch.resolve()
                assert not allocated[0].exists()
            else:
                assert result.verdict is False
                assert result.detail == _BOUNDARY_DETAIL
                assert result.lines == [-1]
                assert allocated == []
            assert {key: os.environ[key] for key in before} == before


@pytest.mark.parametrize("failure", ["exit", "error"])
def test_original_layout_git_probe_refuses_before_allocation(monkeypatch, external_scratch_root, failure):
    from types import SimpleNamespace
    from aegis_core.errors import AegisError
    from aegis_core.verification import mutation_tester

    checkout, other, metadata = (external_scratch_root / part for part in ("B", "A", "metadata.git"))
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(other)], check=True, timeout=30)
    subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True, timeout=30)
    target, test = checkout / "target.py", checkout / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    calls = []

    def refuse(*args, **kwargs):
        calls.append(True)
        if failure == "error":
            raise AegisError("private diagnostic")
        return subprocess.CompletedProcess([], 128, b"", b"private diagnostic")

    def forbidden_allocation(**kwargs):
        raise AssertionError("failed original-layout probe reached scratch allocation")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.gitsafe", SimpleNamespace(
        **{**vars(mutation_tester.gitsafe), "run": refuse},
    ))
    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(external_scratch_root), TemporaryDirectory=forbidden_allocation,
    ))
    with _git_environment(other):
        os.environ.update(GIT_DIR=str(metadata), GIT_WORK_TREE=str(checkout))
        for attempt in range(2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
            assert result.verdict is False
            assert result.detail == _BOUNDARY_DETAIL
            assert "private diagnostic" not in result.detail
            assert result.lines == [-1]
            assert len(calls) == attempt + 1


@pytest.mark.parametrize("name", ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"])
@pytest.mark.parametrize("invalid", ["empty", "missing-parent", "file-parent"])
@pytest.mark.parametrize("absolute", [False, True], ids=["relative", "absolute"])
@pytest.mark.parametrize("inside", [False, True], ids=["outside-cwd", "inside-cwd"])
@pytest.mark.parametrize("suffix", [".py", ".rs"])
def test_explicit_layout_is_validated_as_given(
    monkeypatch, external_scratch_root, name, invalid, absolute, inside, suffix,
):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    checkout, other = external_scratch_root / "B", external_scratch_root / "A"
    metadata = external_scratch_root / "metadata.git"
    package = checkout / "src" / "package"
    package.mkdir(parents=True)
    for root in (checkout, other):
        subprocess.run(["git", "init", "-q", str(root)], check=True, timeout=30)
    subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True, timeout=30)
    target, test = package / ("target" + suffix), package / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    invocation = checkout / "src" if inside else other
    valid = {"GIT_DIR": metadata, "GIT_WORK_TREE": checkout / "src", "GIT_COMMON_DIR": metadata}
    base = valid[name]
    if invalid == "file-parent":
        (base / "blocked").write_text("regular file\n", encoding="utf-8")
    tail = "blocked/.." if invalid == "file-parent" else "missing/.."
    value = str(base / tail) if absolute else os.path.relpath(base, invocation) + "/" + tail
    if invalid == "empty":
        value = ""

    def forbidden_allocation(**kwargs):
        raise AssertionError("invalid original Git layout reached scratch allocation")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(checkout), TemporaryDirectory=forbidden_allocation,
    ))
    with _git_environment(invocation):
        os.environ.update({key: str(path) for key, path in valid.items()})
        os.environ[name] = value
        before = {key: os.environ[key] for key in valid}
        for _ in range(2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
            assert result.verdict is False
            assert result.detail == _INVALID_LAYOUT_DETAIL
            assert not value or value not in result.detail
            assert result.lines == [-1]
            assert {key: os.environ[key] for key in valid} == before


@pytest.mark.parametrize("name", ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"])
@pytest.mark.parametrize("aliased", [False, True], ids=["physical-temp", "symlinked-temp"])
def test_explicit_layout_component_rename_refuses_and_can_be_retried(
    monkeypatch, external_scratch_root, name, aliased,
):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester
    from tests.conftest import symlink_or_skip

    if aliased:
        physical = external_scratch_root / "physical"
        physical.mkdir()
        alias = external_scratch_root / "alias"
        symlink_or_skip(physical, alias, target_is_directory=True)
        external_scratch_root = alias

    checkout, other = external_scratch_root / "B", external_scratch_root / "A"
    metadata = external_scratch_root / "metadata.git"
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(other)], check=True, timeout=30)
    subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True, timeout=30)
    target, test = checkout / "target.py", checkout / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    valid = {"GIT_DIR": metadata, "GIT_WORK_TREE": checkout, "GIT_COMMON_DIR": metadata}
    component = valid[name] / "existing"
    component.mkdir()
    canonical = component.resolve()
    moved = component.with_name("moved")
    renamed = []

    class ConcurrentPath(type(checkout)):
        def resolve(self, *args, **kwargs):
            result = super().resolve(*args, **kwargs)
            if result == canonical and not renamed:
                component.rename(moved)
                renamed.append(True)
            return result

    monkeypatch.setattr("aegis_core.verification.mutation_tester.Path", ConcurrentPath)
    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(external_scratch_root),
        TemporaryDirectory=lambda **kwargs: pytest.fail("layout probe reached allocation"),
    ))
    with _git_environment(other):
        os.environ.update({key: str(path) for key, path in valid.items()})
        os.environ[name] = str(component / "..")
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=0)
        assert result.verdict is False
        assert result.detail == _INVALID_LAYOUT_DETAIL
        assert result.lines == [-1]
        assert renamed == [True]
        assert not component.exists() and moved.is_dir()
        moved.rename(component)
        for _ in range(2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=0)
            assert result.verdict is True
            assert result.detail == "0/0 survived (no mutations to apply)"


@pytest.mark.parametrize("suffix", [".py", ".rs"])
@pytest.mark.parametrize("candidate_at", ["root", "intermediate", "beside"])
@pytest.mark.parametrize("layout", ["missing", "file", "disjoint", "implicit", "valid"])
def test_explicit_worktree_must_be_established_before_allocation(
    monkeypatch, external_scratch_root, suffix, candidate_at, layout,
):
    from types import SimpleNamespace
    from aegis_core.ast.schema import MutationPoint
    from aegis_core.verification import mutation_tester

    checkout, other = external_scratch_root / "B", external_scratch_root / "A"
    metadata_owner = external_scratch_root / "metadata-owner"
    package = checkout / "src" / "package"
    package.mkdir(parents=True)
    for root in (other, metadata_owner):
        subprocess.run(["git", "init", "-q", str(root)], check=True)
    target, test = package / ("target" + suffix), package / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    worktree = external_scratch_root / "unresolved-worktree"
    if layout == "valid":
        worktree = checkout
    elif layout == "file":
        worktree.write_text("regular file\n", encoding="utf-8")
    elif layout == "disjoint":
        worktree.mkdir()
    candidate = checkout if candidate_at == "root" else (
        checkout / "src" if candidate_at == "intermediate" else checkout / "scratch"
    )
    candidate.mkdir(exist_ok=True)

    def forbidden_allocation(**kwargs):
        pytest.fail("unestablished explicit worktree reached scratch allocation")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=forbidden_allocation,
    ))
    point = MutationPoint(line=2, col=0, original_op="+", replacement_op="-")
    runner = SimpleNamespace(parse_file=lambda _: SimpleNamespace(mutation_points=[point]))
    with _git_environment(other):
        os.environ["GIT_CEILING_DIRECTORIES"] = str(external_scratch_root)
        os.environ["GIT_DIR"] = "../metadata-owner/.git"
        if layout != "implicit":
            os.environ["GIT_WORK_TREE"] = "../" + worktree.name
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1, ast_runner=runner)
    if layout == "valid":
        expected = _SCRATCH_INSIDE_DETAIL
    elif layout == "disjoint":
        expected = _BOUNDARY_DETAIL
    else:
        expected = _INVALID_LAYOUT_DETAIL
    assert result.verdict is False
    assert result.detail == expected
    assert result.lines == [-1]


@pytest.mark.parametrize("boundary_owner", ["cwd", "tool"])
def test_explicit_layout_cannot_invent_a_disjoint_context_boundary(
    monkeypatch, external_scratch_root, boundary_owner,
):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    checkout, other = external_scratch_root / "B", external_scratch_root / "A"
    metadata_owner = external_scratch_root / "metadata-owner"
    context = external_scratch_root / "C" / "sub"
    package = checkout / "package"
    package.mkdir(parents=True)
    context.mkdir(parents=True)
    for root in (other, metadata_owner):
        subprocess.run(["git", "init", "-q", str(root)], check=True)
    target, test = package / "target.py", package / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    if boundary_owner == "tool":
        installed = context / "aegis_core" / "verification" / "mutation_tester.py"
        installed.parent.mkdir(parents=True)
        installed.write_text("# fixture module location\n", encoding="utf-8")
        monkeypatch.setattr("aegis_core.verification.mutation_tester.__file__", str(installed))
    invocation = context if boundary_owner == "cwd" else other

    def forbidden_allocation(**kwargs):
        pytest.fail("disjoint context fallback reached scratch allocation")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(context.parent), TemporaryDirectory=forbidden_allocation,
    ))
    with _git_environment(invocation):
        os.environ["GIT_CEILING_DIRECTORIES"] = str(external_scratch_root)
        os.environ["GIT_DIR"] = os.path.relpath(metadata_owner / ".git", invocation)
        os.environ["GIT_WORK_TREE"] = os.path.relpath(checkout, invocation)
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
    assert result.verdict is False
    assert result.detail == _BOUNDARY_DETAIL
    assert result.lines == [-1]


def test_explicit_worktree_must_match_reported_toplevel(monkeypatch, external_scratch_root):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    checkout, other = external_scratch_root / "B", external_scratch_root / "A"
    metadata_owner = external_scratch_root / "metadata-owner"
    package = checkout / "package"
    package.mkdir(parents=True)
    for root in (other, metadata_owner):
        subprocess.run(["git", "init", "-q", str(root)], check=True)
    target, test = package / "target.py", package / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    candidate = external_scratch_root / "external-scratch"
    candidate.mkdir()

    def forbidden_allocation(**kwargs):
        pytest.fail("mismatched native toplevel reached scratch allocation")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=forbidden_allocation,
    ))
    monkeypatch.setattr("aegis_core.verification.mutation_tester.gitsafe", SimpleNamespace(
        **{**vars(mutation_tester.gitsafe), "toplevel": lambda _: other},
    ))
    with _git_environment(other):
        os.environ["GIT_CEILING_DIRECTORIES"] = str(external_scratch_root)
        os.environ["GIT_DIR"] = "../metadata-owner/.git"
        os.environ["GIT_WORK_TREE"] = "../B"
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
    assert result.verdict is False
    assert result.detail == _BOUNDARY_DETAIL
    assert result.lines == [-1]


@pytest.mark.parametrize("name", ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"])
@pytest.mark.parametrize("malformed", ["oversized", "nul", "expanded"])
def test_git_layout_limits_refuse_before_path_or_runner(tmp_path, monkeypatch, name, malformed):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    target, test = tmp_path / "target.py", tmp_path / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    value = "private\x00diagnostic" if malformed == "nul" else "x" * (65537 if malformed == "oversized" else 65536)

    class BoundedPath(type(tmp_path)):
        def __truediv__(self, part):
            if malformed != "expanded" and part == value:
                pytest.fail("invalid Git layout reached path parsing")
            return super().__truediv__(part)

    def forbidden_runner(**kwargs):
        pytest.fail("invalid Git layout reached the runner")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.Path", BoundedPath)
    monkeypatch.setattr("aegis_core.verification.mutation_tester.gitsafe", SimpleNamespace(
        **{**vars(mutation_tester.gitsafe), "custody": forbidden_runner},
    ))
    # Model the OS boundary without putenv rejecting malformed/oversized values
    # first (Windows also bounds individual environment values).
    monkeypatch.setattr("aegis_core.verification.mutation_tester.os", SimpleNamespace(
        **{**vars(os), "environ": {name: value}},
    ))
    result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
    assert result.verdict is False
    assert result.detail == _INVALID_LAYOUT_DETAIL
    assert value not in result.detail
    assert result.lines == [-1]


def test_nonexistent_git_dir_refuses_before_custody(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from aegis_core.errors import AegisError
    from aegis_core.verification import mutation_tester

    target, test = tmp_path / "target.py", tmp_path / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    calls = []

    def refused_runner(**kwargs):
        calls.append(kwargs)
        raise AegisError("private diagnostic")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.gitsafe", SimpleNamespace(
        **{**vars(mutation_tester.gitsafe), "custody": refused_runner},
    ))
    with _git_environment():
        os.environ["GIT_DIR"] = str(tmp_path / "missing.git")
        os.environ["GIT_WORK_TREE"] = str(tmp_path)
        for _ in range(2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
            assert result.verdict is False
            assert result.detail == _INVALID_LAYOUT_DETAIL
            assert "private diagnostic" not in result.detail
            assert result.lines == [-1]
            assert calls == []


def test_git_runner_policy_refusal_has_fixed_public_message(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from aegis_core.errors import AegisError
    from aegis_core.verification import mutation_tester

    target, test = tmp_path / "target.py", tmp_path / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    metadata = tmp_path / "metadata.git"
    subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True, timeout=30)
    calls = []

    def refused_runner(**kwargs):
        calls.append(kwargs)
        raise AegisError("private diagnostic")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.gitsafe", SimpleNamespace(
        **{**vars(mutation_tester.gitsafe), "custody": refused_runner},
    ))
    with _git_environment():
        os.environ["GIT_DIR"] = str(metadata)
        os.environ["GIT_WORK_TREE"] = str(tmp_path)
        native = subprocess.run(
            ["git", "-C", str(tmp_path), "rev-parse", "--show-toplevel"],
            check=True, capture_output=True, text=True, timeout=30,
        )
        assert Path(native.stdout.strip()).resolve() == tmp_path.resolve()
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
    assert result.verdict is False
    assert result.detail == _BOUNDARY_DETAIL
    assert "private diagnostic" not in result.detail
    assert result.lines == [-1]
    assert len(calls) == 1


def test_explicit_layout_preserves_closest_marker_boundary(monkeypatch, external_scratch_root):
    from types import SimpleNamespace
    from aegis_core.ast.schema import MutationPoint
    from aegis_core.verification import mutation_tester

    checkout, other = external_scratch_root / "B", external_scratch_root / "A"
    nested = checkout / "nested"
    package = nested / "package"
    package.mkdir(parents=True)
    for root in (other, nested):
        subprocess.run(["git", "init", "-q", str(root)], check=True)
    metadata = external_scratch_root / "metadata.git"
    subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True)
    target, test = package / "target.rs", package / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    candidate = checkout / "scratch"
    candidate.mkdir()
    monkeypatch.setattr("aegis_core.verification.mutation_tester.__file__",
                        str(other / "aegis_core" / "verification" / "mutation_tester.py"))
    real_tempfile = mutation_tester.tempfile
    allocated = []

    def allocate(**kwargs):
        manager = real_tempfile.TemporaryDirectory(**kwargs)
        allocated.append(Path(manager.name))
        return manager

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=allocate,
    ))
    point = MutationPoint(line=2, col=0, original_op="+", replacement_op="-")
    runner = SimpleNamespace(parse_file=lambda _: SimpleNamespace(mutation_points=[point]))
    with _git_environment(other):
        os.environ.update(GIT_DIR=str(metadata), GIT_WORK_TREE=str(checkout))
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1, ast_runner=runner)
    assert "survived" in result.detail, result.detail
    assert len(allocated) == 1
    assert allocated[0].parent == candidate.resolve()
    assert not allocated[0].exists()


@pytest.mark.parametrize("index_mode", ["100644", "100755"])
@pytest.mark.parametrize("replacement", ["symlink", "fifo"])
@pytest.mark.parametrize("surface", ["tree_counts", "file_counts"])
def test_indexed_regular_replaced_after_lstat_refuses(tmp_path, index_mode, replacement, surface):
    from tests.conftest import symlink_or_skip

    if replacement == "fifo" and (os.name != "posix" or not hasattr(os, "mkfifo")):
        pytest.skip("FIFO creation requires POSIX mkfifo")
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    path = checkout / "sample.py"
    path.write_text("LABEL = " + repr(REQUIRED_WORDS[0]) + "\n", encoding="utf-8")
    subprocess.run(["git", "add", "sample.py"], cwd=checkout, check=True)
    subprocess.run(["git", "update-index", "--chmod=" + ("+x" if index_mode == "100755" else "-x"),
                    "sample.py"], cwd=checkout, check=True)
    readable = tmp_path / "readable.py"
    readable.write_text("pass\n", encoding="utf-8")
    prepared = tmp_path / "prepared"
    if replacement == "symlink":
        symlink_or_skip(readable, prepared)
    else:
        os.mkfifo(prepared)
    # A child bounds the old FIFO hang and is killed/reaped by subprocess.run.
    script = '''
import os
from pathlib import Path
import sys
from tests.contract.test_legacy_ratchet import REQUIRED_WORDS, file_counts, tree_counts

checkout, prepared, surface = sys.argv[1:]
class SwapPath(type(Path())):
    def lstat(self):
        before = super().lstat()
        if self.name == "sample.py":
            os.replace(prepared, self)
        return before

root = SwapPath(checkout)
try:
    if surface == "tree_counts":
        tree_counts({}, root)
    else:
        file_counts(root / "sample.py", root, REQUIRED_WORDS)
except ValueError as exc:
    assert str(exc) == "cannot read listed text file", str(exc)
else:
    raise AssertionError("replacement was read instead of refused")
'''
    try:
        done = subprocess.run([sys.executable, "-c", script, str(checkout), str(prepared), surface],
                              cwd=REPO, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        pytest.fail("regular-file read blocked on a replacement FIFO")
    assert done.returncode == 0, done.stdout + done.stderr


@pytest.mark.parametrize("replace", [False, True], ids=["same-object", "different-object"])
def test_regular_read_without_nofollow_checks_opened_identity(tmp_path, monkeypatch, replace):
    from types import SimpleNamespace

    path, other = tmp_path / "sample.py", tmp_path / "other.py"
    path.write_text("LABEL = " + repr(REQUIRED_WORDS[0]) + "\n", encoding="utf-8")
    other.write_text("pass\n", encoding="utf-8")
    original_os, opened = os, []

    def open_file(candidate, flags):
        fd = original_os.open(other if replace else candidate, flags)
        opened.append(fd)
        return fd

    # Exercise the Windows-equivalent identity path on every host.
    monkeypatch.setattr("tests.contract.test_legacy_ratchet.os", SimpleNamespace(
        **{**vars(os), "O_NOFOLLOW": 0, "O_NONBLOCK": 0, "open": open_file},
    ))
    if replace:
        with pytest.raises(ValueError, match="^cannot read listed text file$"):
            file_counts(path, tmp_path, REQUIRED_WORDS)
    else:
        assert file_counts(path, tmp_path, REQUIRED_WORDS)[REQUIRED_WORDS[0]] == 1
    assert len(opened) == 1
    with pytest.raises(OSError) as exc:
        original_os.fstat(opened[0])
    import errno
    assert exc.value.errno == errno.EBADF


@pytest.mark.parametrize("tracked", [False, True], ids=["untracked", "tracked"])
@pytest.mark.parametrize("removal", ["file", "parent", "parent-replaced"])
def test_listing_to_read_removal_is_classified(tmp_path, monkeypatch, tracked, removal):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    path = tmp_path / "notes" / "sample.py"
    path.parent.mkdir()
    path.write_text("LABEL = " + repr(REQUIRED_WORDS[0]) + "\n", encoding="utf-8")
    if tracked:
        subprocess.run(["git", "add", "notes/sample.py"], cwd=tmp_path, check=True)
    original = repository_files
    listed_ready, resume_read = Event(), Event()

    def list_then_wait(root):
        listed = original(root)
        listed_ready.set()
        assert resume_read.wait(5), "test did not release scanner read"
        return listed

    monkeypatch.setattr("tests.contract.test_legacy_ratchet.repository_files", list_then_wait)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            scan = pool.submit(tree_counts, {}, tmp_path)
            try:
                assert listed_ready.wait(5), "scanner did not finish listing"
                path.unlink()
                if removal != "file":
                    path.parent.rmdir()
                if removal == "parent-replaced":
                    path.parent.write_text("replacement", encoding="utf-8")
            finally:
                resume_read.set()
            if tracked:
                with pytest.raises(ValueError, match="^cannot read listed text file$"):
                    scan.result(timeout=5)
            else:
                assert not any(scan.result(timeout=5)[0].values())
    finally:
        monkeypatch.setattr("tests.contract.test_legacy_ratchet.repository_files", original)
    if removal == "parent-replaced":
        path.parent.unlink()
    path.parent.mkdir(exist_ok=True)
    path.write_text("LABEL = " + repr(REQUIRED_WORDS[0]) + "\n", encoding="utf-8")
    assert tree_counts({}, tmp_path)[0][REQUIRED_WORDS[0]] == 1


@pytest.mark.parametrize("tracked", [False, True], ids=["untracked", "tracked"])
@pytest.mark.parametrize("original_type,replacement", [
    ("regular", "directory"), ("regular", "symlink"), ("regular", "fifo"),
    ("symlink", "regular"), ("symlink", "directory"), ("symlink", "fifo"),
])
def test_listed_file_type_replacement_is_classified(tmp_path, monkeypatch, tracked, original_type, replacement):
    from tests.conftest import symlink_or_skip

    if replacement == "fifo" and (os.name != "posix" or not hasattr(os, "mkfifo")):
        pytest.skip("FIFO creation requires POSIX mkfifo")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    path = tmp_path / "sample.py"
    if original_type == "symlink":
        symlink_or_skip(REQUIRED_WORDS[0], path)
    else:
        path.write_text("LABEL = " + repr(REQUIRED_WORDS[0]) + "\n", encoding="utf-8")
    if tracked:
        subprocess.run(["git", "add", "sample.py"], cwd=tmp_path, check=True)
    original = repository_files

    def list_then_replace(root):
        listed = original(root)
        path.unlink()
        if replacement == "directory":
            path.mkdir()
        elif replacement == "regular":
            path.write_text("LABEL = " + repr(REQUIRED_WORDS[0]) + "\n", encoding="utf-8")
        elif replacement == "symlink":
            symlink_or_skip("missing-target", path)
        else:
            os.mkfifo(path)
        return listed

    monkeypatch.setattr("tests.contract.test_legacy_ratchet.repository_files", list_then_replace)
    try:
        if tracked:
            with pytest.raises(ValueError, match="^cannot read listed text file$"):
                tree_counts({}, tmp_path)
        else:
            assert tree_counts({}, tmp_path)[0][REQUIRED_WORDS[0]] == (1 if replacement == "regular" else 0)
    finally:
        monkeypatch.setattr("tests.contract.test_legacy_ratchet.repository_files", original)
    if replacement == "directory":
        path.rmdir()
    else:
        path.unlink()
    if original_type == "symlink":
        symlink_or_skip(REQUIRED_WORDS[0], path)
    else:
        path.write_text("LABEL = " + repr(REQUIRED_WORDS[0]) + "\n", encoding="utf-8")
    assert tree_counts({}, tmp_path)[0][REQUIRED_WORDS[0]] == 1


def test_indexed_directory_entry_is_not_read_as_source(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "submodule").mkdir()
    subprocess.run(["git", "update-index", "--add", "--cacheinfo", "160000," + "1" * 40 + ",submodule"],
                   cwd=tmp_path, check=True)
    counts, _, files = tree_counts({}, tmp_path)
    assert not any(counts.values())
    assert "submodule" not in files


def test_unmerged_index_refuses_with_fixed_listing_message(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "sample.py").write_text("LABEL = 0\n", encoding="utf-8")
    blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=tmp_path,
                          input=b"LABEL = 0\n", check=True, stdout=subprocess.PIPE).stdout.strip()
    subprocess.run(["git", "update-index", "--index-info"], cwd=tmp_path, check=True,
                   input=b"100644 " + blob + b" 1\tsample.py\n")
    with pytest.raises(ValueError, match="^cannot list repository files$"):
        tree_counts({}, tmp_path)


def test_executable_index_mode_is_still_regular_source(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    path = tmp_path / "sample.py"
    path.write_text("LABEL = " + repr(REQUIRED_WORDS[0]) + "\n", encoding="utf-8")
    subprocess.run(["git", "add", "sample.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "update-index", "--chmod=+x", "sample.py"], cwd=tmp_path, check=True)
    assert tree_counts({}, tmp_path)[0][REQUIRED_WORDS[0]] == 1


def test_python_count_and_ast_share_one_read(tmp_path, monkeypatch):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    path = tmp_path / "sample.py"
    path.write_text("import " + REQUIRED_WORDS[0] + "_x\n", encoding="utf-8")
    original = _tracked_text
    reads = []

    def read_then_remove(*args, **kwargs):
        content = original(*args, **kwargs)
        reads.append(args[0])
        path.unlink()
        return content

    monkeypatch.setattr("tests.contract.test_legacy_ratchet._tracked_text", read_then_remove)
    counts, _, _ = tree_counts({}, tmp_path)
    assert reads == [path]
    assert counts[REQUIRED_WORDS[0]] == 1
    assert counts[ZERO_ROWS[0]] == 1


def test_present_mutation_scratch_is_refused(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    path = tmp_path / "aegis-mutants-example" / "_aegis_mutant_swap.py"
    path.parent.mkdir()
    path.write_text("LABEL = " + repr(REQUIRED_WORDS[0]) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="^mutation scratch present in repository$"):
        tree_counts({}, tmp_path)


@pytest.mark.parametrize("tracked", [False, True], ids=["untracked", "tracked"])
@pytest.mark.parametrize("operation", ["lstat", "open", "fstat", "fdopen", "read"])
def test_scanner_io_errors_refuse_then_retry(tmp_path, monkeypatch, tracked, operation):
    import errno
    from types import SimpleNamespace

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    path = tmp_path / "sample.py"
    path.write_text("LABEL = " + repr(REQUIRED_WORDS[0]) + "\n", encoding="utf-8")
    if tracked:
        subprocess.run(["git", "add", "sample.py"], cwd=tmp_path, check=True)

    class FailingPath(type(tmp_path)):
        def lstat(self):
            if self.name == path.name and operation == "lstat":
                raise PermissionError("private diagnostic")
            return super().lstat()

    original_os, opened = os, []

    def open_file(*args, **kwargs):
        if operation == "open":
            raise PermissionError("private diagnostic")
        fd = original_os.open(*args, **kwargs)
        opened.append(fd)
        return fd

    def fstat(fd):
        if operation == "fstat":
            raise OSError("private diagnostic")
        return original_os.fstat(fd)

    def fdopen(*args, **kwargs):
        if operation == "fdopen":
            raise OSError("private diagnostic")

        return read_stream(*args, **kwargs)

    @contextmanager
    def read_stream(*args, **kwargs):
        with original_os.fdopen(*args, **kwargs) as stream:
            def refused_read():
                raise OSError("private diagnostic")
            yield SimpleNamespace(read=refused_read) if operation == "read" else stream

    monkeypatch.setattr("tests.contract.test_legacy_ratchet.os", SimpleNamespace(
        **{**vars(os), "open": open_file, "fstat": fstat, "fdopen": fdopen},
    ))
    try:
        with pytest.raises(ValueError, match="^cannot read listed text file$"):
            tree_counts({}, FailingPath(tmp_path))
    finally:
        monkeypatch.setattr("tests.contract.test_legacy_ratchet.os", original_os)
    assert len(opened) == (0 if operation in ("lstat", "open") else 1)
    for fd in opened:
        with pytest.raises(OSError) as exc:
            original_os.fstat(fd)
        assert exc.value.errno == errno.EBADF
    assert tree_counts({}, tmp_path)[0][REQUIRED_WORDS[0]] == 1


@pytest.mark.parametrize("tracked", [False, True], ids=["untracked", "tracked"])
@pytest.mark.parametrize("failure", ["vanished", "permission"])
def test_symlink_read_failure_is_classified_then_retried(tmp_path, monkeypatch, tracked, failure):
    from types import SimpleNamespace
    from tests.conftest import symlink_or_skip

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    link = tmp_path / "sample.link"
    symlink_or_skip(REQUIRED_WORDS[0], link)
    if tracked:
        subprocess.run(["git", "add", "sample.link"], cwd=tmp_path, check=True)
    real_os = os
    real_readlink = os.readlink

    def refused_readlink(path):
        if failure == "permission":
            raise PermissionError("private diagnostic")
        link.unlink()
        return real_readlink(path)

    os_api = SimpleNamespace(**{**vars(os), "readlink": refused_readlink})
    monkeypatch.setattr("tests.contract.test_legacy_ratchet.os", os_api)
    try:
        if tracked or failure == "permission":
            with pytest.raises(ValueError, match="^cannot read listed text file$"):
                tree_counts({}, tmp_path)
        else:
            assert not any(tree_counts({}, tmp_path)[0].values())
    finally:
        monkeypatch.setattr("tests.contract.test_legacy_ratchet.os", real_os)
    if failure == "vanished":
        symlink_or_skip(REQUIRED_WORDS[0], link)
    assert tree_counts({}, tmp_path)[0][REQUIRED_WORDS[0]] == 1


def test_all_counts_match_their_nonincreasing_records():
    data = _data()
    counts, deferred, files = tree_counts(data)
    offenders = {rel: {k: v for k, v in count.items() if v} for rel, count in files.items() if any(count.values())}
    assert counts == data["counts"], offenders
    assert deferred == {rel: entry["counts"] for rel, entry in data["deferred"].items()}


def test_repository_rules_load_after_file_renames():
    from aegis_core.rules import load_rules

    assert load_rules(REPO).errors == ()


def test_the_tree_counter_covers_comments_docs_root_config_and_names(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for folder in ("tools", "tests", "docs", ".aegis", "skills", "governance"):
        target = tmp_path / folder / "sample.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(REQUIRED_WORDS[0], encoding="utf-8")
    (tmp_path / "settings.ini").write_text(REQUIRED_WORDS[0], encoding="utf-8")
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / (REQUIRED_WORDS[0] + ".py")).write_text(
        '"""' + REQUIRED_WORDS[0] + '"""\n# ' + REQUIRED_WORDS[0] + '\n', encoding="utf-8",
    )
    assert tree_counts({}, tmp_path)[0][REQUIRED_WORDS[0]] == 10


def test_plural_camel_case_names_and_substrings():
    word = REQUIRED_WORDS[1]
    assert _word_counts([word + " " + word + "s " + word.capitalize() + "Registry cancel firewall"], (word,)) == {word: 3}


def test_escaped_line_breaks_do_not_hide_string_vocabulary(tmp_path):
    word = REQUIRED_WORDS[0]
    path = tmp_path / "sample.py"
    path.write_text("LABEL = " + repr("\n" + word + "\t" + word), encoding="utf-8")
    assert file_counts(path, tmp_path, (word,)) == {word: 2}


def test_brand_prefix_in_compound_file_and_symbol_names_is_counted():
    word = REQUIRED_WORDS[0]
    assert _word_counts(["test_" + word + "yaml.py"], (word,)) == {word: 1}


@pytest.mark.parametrize("encoding", ["adjacent", "escaped"])
def test_decoded_python_literals_cannot_hide_vocabulary(tmp_path, encoding):
    word = REQUIRED_WORDS[0]
    literal = ('"' + word[:2] + '" "' + word[2:] + '"' if encoding == "adjacent"
               else '"\\x' + format(ord(word[0]), '02x') + word[1:] + '"')
    path = tmp_path / "sample.py"
    path.write_text("LABEL = " + literal + "\n", encoding="utf-8")
    assert file_counts(path, tmp_path, (word,))[word] == 1


def test_an_undecodable_tracked_file_is_refused_with_a_stable_message(tmp_path):
    word = REQUIRED_WORDS[0]
    path = tmp_path / "sample.sh"
    path.write_bytes(b"printf " + word.encode() + b"\n# \xff\n")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "add", "sample.sh"], cwd=tmp_path, check=True)
    with pytest.raises(ValueError, match="^cannot decode tracked text file: sample.sh$"):
        tree_counts({}, tmp_path)


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-32", "utf-16-be", "utf-32-be"])
def test_bom_encoded_tracked_markdown_is_counted(tmp_path, encoding):
    import codecs

    path = tmp_path / "docs/notes.md"
    path.parent.mkdir()
    raw = (REQUIRED_WORDS[0] + "\n").encode(encoding)
    if encoding == "utf-16-be":
        raw = codecs.BOM_UTF16_BE + raw
    elif encoding == "utf-32-be":
        raw = codecs.BOM_UTF32_BE + raw
    path.write_bytes(raw)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "add", "docs/notes.md"], cwd=tmp_path, check=True)
    assert tree_counts({}, tmp_path)[0][REQUIRED_WORDS[0]] == 1


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
def test_bomless_unicode_tracked_markdown_is_refused(tmp_path, encoding):
    path = tmp_path / "docs/notes.md"
    path.parent.mkdir()
    path.write_bytes((REQUIRED_WORDS[0] + "\n").encode(encoding))
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "add", "docs/notes.md"], cwd=tmp_path, check=True)
    with pytest.raises(ValueError, match="^cannot decode tracked text file: docs/notes.md$"):
        tree_counts({}, tmp_path)


def test_documented_removals_still_pass_when_unreleased_becomes_a_release(tmp_path):
    data = _data()
    source = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    path = tmp_path / "CHANGELOG.md"
    path.write_text(source.replace("## [Unreleased]", "## [5.0.0] - 2026-12-01", 1), encoding="utf-8")
    assert not any(file_counts(path, tmp_path, REQUIRED_WORDS,
                              history=[*data["historical_sections"], *data["documented_removals"]]).values())


def test_symlink_target_text_is_counted_without_following_it(tmp_path):
    from tests.conftest import symlink_or_skip

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    link = tmp_path / "legacy-dir"
    symlink_or_skip("." + REQUIRED_WORDS[0], link, target_is_directory=True)
    subprocess.run(["git", "add", "legacy-dir"], cwd=tmp_path, check=True)
    assert tree_counts({}, tmp_path)[0][REQUIRED_WORDS[0]] == 1
    assert not link.exists()


def test_timing_phrases_are_location_independent(tmp_path):
    path = tmp_path / "timing.py"
    phrase = REQUIRED_WORDS[4] + "_clock"
    path.write_text("\n" * 20 + phrase + " = 0\n")
    assert file_counts(path, tmp_path, REQUIRED_WORDS)[REQUIRED_WORDS[4]] == 0


def test_a_new_release_section_is_not_implicitly_historical(tmp_path):
    path = tmp_path / "CHANGELOG.md"
    word = REQUIRED_WORDS[0]
    path.write_text("## [Unreleased]\n\n## [5.0.0]\n" + word + "\n\n## [4.5.0] - 2026-11-02\n" + word, encoding="utf-8")
    assert file_counts(path, tmp_path, (word,), history=_data()["historical_sections"])[word] == 1


@pytest.mark.parametrize("word_index,plural,prefix", [(19, "", "aws"), (6, "s", ".aegis\\rules")])
def test_backslashes_preserve_the_following_letters(word_index, plural, prefix):
    word = REQUIRED_WORDS[word_index]
    assert _word_counts([prefix + "\\" + word + plural + "\\x.md"], (word,))[word] == 1


@pytest.mark.parametrize("category", ["deferred", "exempt_files"])
@pytest.mark.parametrize("kind,row", [("import", ZERO_ROWS[0]), ("class", ZERO_ROWS[1])])
def test_zero_floors_include_deferred_and_exempt_python(tmp_path, category, kind, row):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    rel = "aegis_cli/cli.py"
    path = tmp_path / rel
    path.parent.mkdir()
    word = REQUIRED_WORDS[0]
    statement = "import " + word + "_x\n" if kind == "import" else "class " + word.capitalize() + "X: pass\n"
    path.write_text(statement, encoding="utf-8")
    assert tree_counts({category: {rel: {}}}, tmp_path)[0][row] == 1


def test_a_blank_line_in_another_file_keeps_the_tree_at_zero(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    rel = "aegis_cli/ui/table.py"
    path = tmp_path / rel
    path.parent.mkdir(parents=True)
    source = (REPO / rel).read_text(encoding="utf-8")
    path.write_text(source, encoding="utf-8")
    assert not any(tree_counts(_data(), tmp_path)[0].values())
    path.write_text("\n" + source, encoding="utf-8")
    assert not any(tree_counts(_data(), tmp_path)[0].values())


@pytest.mark.parametrize("expression", ['"{a}" + "{b}"', '("{a}" + "{b}") + ""', 'b"{a}" + b"{b}"'])
def test_constant_additions_cannot_hide_vocabulary(tmp_path, expression):
    word = REQUIRED_WORDS[0]
    path = tmp_path / "sample.py"
    path.write_text("LABEL = " + expression.format(a=word[:2], b=word[2:]) + "\n")
    assert file_counts(path, tmp_path, (word,))[word] == 1


@pytest.mark.parametrize("position", ["key", "value"])
def test_json_escapes_cannot_hide_vocabulary(tmp_path, position):
    word = REQUIRED_WORDS[0]
    encoded = "\\u" + format(ord(word[0]), "04x") + word[1:]
    path = tmp_path / "sample.json"
    path.write_text('{"' + (encoded if position == "key" else "name") + '":"' + (encoded if position == "value" else "name") + '"}')
    assert file_counts(path, tmp_path, (word,))[word] == 1


def test_writer_can_lower_but_never_raise_or_add_a_positive_record():
    assert lowered({"old": 2}, {"old": 1}) == {"old": 1}
    for current in ({"old": 3}, {"old": 2, "new": 1}):
        with pytest.raises(ValueError, match="^refusing to raise records:"):
            lowered({"old": 2}, current)


def test_removed_and_ignored_files_are_not_counted(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    target = tmp_path / "old.txt"
    target.write_text(REQUIRED_WORDS[0], encoding="utf-8")
    subprocess.run(["git", "add", "old.txt"], cwd=tmp_path, check=True)
    target.unlink()
    (tmp_path / ".gitignore").write_text("generated/\n", encoding="utf-8")
    ignored = tmp_path / "generated" / "output.txt"
    ignored.parent.mkdir()
    ignored.write_text(REQUIRED_WORDS[0], encoding="utf-8")
    assert tree_counts({}, tmp_path)[0][REQUIRED_WORDS[0]] == 0


def test_retired_type_words_are_not_normalized():
    from aegis_core.taxonomy import legacy_rule_type
    assert {word: legacy_rule_type(word) for word in REQUIRED_WORDS if legacy_rule_type(word)} == {}


def test_retired_layout_is_refused_generically(tmp_path):
    from aegis_core.errors import WorkspaceError
    from aegis_core.workspace.base import Workspace
    (tmp_path / ("." + REQUIRED_WORDS[0]) / (REQUIRED_WORDS[1] + "s")).mkdir(parents=True)
    with pytest.raises(WorkspaceError, match=r"^not a valid Aegis workspace \(missing \.aegis/rules\): "):
        Workspace.confine(tmp_path)


def test_retired_ledger_keys_are_unusable():
    from aegis_core.telemetry_engine import ledger
    for key in (REQUIRED_WORDS[1], REQUIRED_WORDS[1] + "_id", REQUIRED_WORDS[1] + "s_used"):
        value = ["trap-x"] if key.endswith("_used") else "trap-x"
        assert ledger.normalize_rows([{key: value, "signal": "tp"}]) == ([], 1)


def write_record():
    data = _data()
    check_exclusion_keys(data)
    counts, deferred, _ = tree_counts(data)
    data["counts"] = lowered(data["counts"], counts)
    for rel, entry in data["deferred"].items():
        entry["counts"] = lowered(entry["counts"], deferred.get(rel, {}))
    RECORD.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        sys.exit("usage: PYTHONPATH=. python3 tests/contract/test_legacy_ratchet.py --write")
    try:
        sys.exit(write_record())
    except ValueError as exc:
        sys.exit(str(exc))
