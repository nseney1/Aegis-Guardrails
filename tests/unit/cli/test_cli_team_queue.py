"""Public queue command behaviour, envelopes, refusals and core parity."""
import json
import hashlib
import errno
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from contextlib import closing, contextmanager
from types import SimpleNamespace

import pytest
import aegis_core.gitsafe as compatibility_git

from aegis_cli.cli import main
from aegis_cli import team as cli_team
from aegis_cli import msg as cli_msg
from aegis_core import events, message_codec, model_select, storage, team, team_claims, team_profile, team_queue
from aegis_core import team_writer_binding as binding


# Captured on b13c9d8e before the adapter/policy move. Each digest covers the
# exact exit code, stdout bytes and stderr bytes (clock/root normalized, plus
# the cwd prefix of an oversized filename in an OS diagnostic).
CLI_PATHS = (
    "team model", "team queue add", "team queue list", "team queue claim",
    "team queue release", "team queue done", "team queue unclaim",
    "team queue audit", "team queue compact", "team config show",
    "team config presets", "team config init", "team doctor", "team hosts",
    "team claim", "team renew", "team transfer", "team release", "team gc",
    "team list", "team status", "team metrics", "msg write", "msg read", "msg verify",
)
CLI_BYTE_GOLDENS = {'team model/text/help': '532200670f8b5b09d6cb0987738defddab0a924ff678f6403a80207f5079c450',
 'team model/text/missing': '532200670f8b5b09d6cb0987738defddab0a924ff678f6403a80207f5079c450',
 'team model/text/malformed': '532200670f8b5b09d6cb0987738defddab0a924ff678f6403a80207f5079c450',
 'team model/text/oversized': '532200670f8b5b09d6cb0987738defddab0a924ff678f6403a80207f5079c450',
 'team model/json/help': '532200670f8b5b09d6cb0987738defddab0a924ff678f6403a80207f5079c450',
 'team model/json/missing': '532200670f8b5b09d6cb0987738defddab0a924ff678f6403a80207f5079c450',
 'team model/json/malformed': '532200670f8b5b09d6cb0987738defddab0a924ff678f6403a80207f5079c450',
 'team model/json/oversized': '532200670f8b5b09d6cb0987738defddab0a924ff678f6403a80207f5079c450',
 'team queue add/text/help': '266324de5cc0ff9c1440c0ecbc847cae74c9fd9cf151989d688a1834d88da4ff',
 'team queue add/text/missing': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue add/text/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue add/text/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue add/json/help': '266324de5cc0ff9c1440c0ecbc847cae74c9fd9cf151989d688a1834d88da4ff',
 'team queue add/json/missing': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue add/json/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue add/json/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue list/text/help': 'f2d83a86f41a9ea3b2cfdd2384ed3c673c6663da6e7f4dfa132367a5d9c40410',
 'team queue list/text/missing': '4b305060eb0acb7ee5f98f87d2e7470f05191f720c2fe51ef1c1fa0e41deb31e',
 'team queue list/text/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue list/text/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue list/json/help': 'f2d83a86f41a9ea3b2cfdd2384ed3c673c6663da6e7f4dfa132367a5d9c40410',
 'team queue list/json/missing': '4b305060eb0acb7ee5f98f87d2e7470f05191f720c2fe51ef1c1fa0e41deb31e',
 'team queue list/json/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue list/json/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue claim/text/help': '30a7f84d0fe47e6658f0de8895fb415554abe022c91be5e9b43a55bd1a8a39e9',
 'team queue claim/text/missing': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue claim/text/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue claim/text/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue claim/json/help': '30a7f84d0fe47e6658f0de8895fb415554abe022c91be5e9b43a55bd1a8a39e9',
 'team queue claim/json/missing': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue claim/json/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue claim/json/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue release/text/help': 'd0f117090e6320de10fe8ece0caf4b7f003bcd5687f7edcbe41f7b4600725045',
 'team queue release/text/missing': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue release/text/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue release/text/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue release/json/help': 'd0f117090e6320de10fe8ece0caf4b7f003bcd5687f7edcbe41f7b4600725045',
 'team queue release/json/missing': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue release/json/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue release/json/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue done/text/help': '11ac62e75dc5fe0ebea6216b18171aa09a3d64cc8a33ec83dfd752e660b8a49d',
 'team queue done/text/missing': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue done/text/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue done/text/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue done/json/help': '11ac62e75dc5fe0ebea6216b18171aa09a3d64cc8a33ec83dfd752e660b8a49d',
 'team queue done/json/missing': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue done/json/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue done/json/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue unclaim/text/help': 'b66d7268882279c0e8cf67e6357a2c4ec6ff355a3fb06898967238e837429332',
 'team queue unclaim/text/missing': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue unclaim/text/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue unclaim/text/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue unclaim/json/help': 'b66d7268882279c0e8cf67e6357a2c4ec6ff355a3fb06898967238e837429332',
 'team queue unclaim/json/missing': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue unclaim/json/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue unclaim/json/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue audit/text/help': '93e29c32f65fb5f51c3562d1210afeb75ac00735443c69ab1ebcfe64e859a757',
 'team queue audit/text/missing': '1009cc95cc9349829123a6f1ed3de48ef77d139a2801a81b4911f8bd0b00b958',
 'team queue audit/text/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue audit/text/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue audit/json/help': '93e29c32f65fb5f51c3562d1210afeb75ac00735443c69ab1ebcfe64e859a757',
 'team queue audit/json/missing': '1009cc95cc9349829123a6f1ed3de48ef77d139a2801a81b4911f8bd0b00b958',
 'team queue audit/json/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue audit/json/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue compact/text/help': 'b70562a9650a8d54dd0e04a4f2c05037bbe31e522694c50f506ca62c6fa777ee',
 'team queue compact/text/missing': '6b4c6c6a7293af88d3d74576e5c839e7b77f129631379b34821484022fc99553',
 'team queue compact/text/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue compact/text/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue compact/json/help': 'b70562a9650a8d54dd0e04a4f2c05037bbe31e522694c50f506ca62c6fa777ee',
 'team queue compact/json/missing': '6b4c6c6a7293af88d3d74576e5c839e7b77f129631379b34821484022fc99553',
 'team queue compact/json/malformed': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team queue compact/json/oversized': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'team config show/text/help': '99b4216fef9182f001615d635b089d074c3a8f9ac963883d47aa56d96f770e3c',
 'team config show/text/missing': 'c2093ef430433606f8499845ed404a4368c8c6dc11a89968074b3a6833980f79',
 'team config show/text/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team config show/text/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team config show/json/help': '99b4216fef9182f001615d635b089d074c3a8f9ac963883d47aa56d96f770e3c',
 'team config show/json/missing': 'c2093ef430433606f8499845ed404a4368c8c6dc11a89968074b3a6833980f79',
 'team config show/json/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team config show/json/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team config presets/text/help': 'e8eb19bd881f1b7fee1552302b2a33a62ca483ffd410f5851845145d9670caf3',
 'team config presets/text/missing': '4ae3b1aa0c338cce28e5573f59bbffecfba0011966d5004204c65109a798f44a',
 'team config presets/text/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team config presets/text/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team config presets/json/help': 'e8eb19bd881f1b7fee1552302b2a33a62ca483ffd410f5851845145d9670caf3',
 'team config presets/json/missing': '4ae3b1aa0c338cce28e5573f59bbffecfba0011966d5004204c65109a798f44a',
 'team config presets/json/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team config presets/json/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team config init/text/help': 'e00cc1e53da57243512a62ccd9164969d69a616b50ff4bc4a6fe7a6fc3634f2d',
 'team config init/text/missing': 'ec61e69a2071684446d63ca7f3e396c08b49dff19ad3cba9b8bd46d2ed6494ec',
 'team config init/text/malformed': 'ec61e69a2071684446d63ca7f3e396c08b49dff19ad3cba9b8bd46d2ed6494ec',
 'team config init/text/oversized': 'ec61e69a2071684446d63ca7f3e396c08b49dff19ad3cba9b8bd46d2ed6494ec',
 'team config init/json/help': 'e00cc1e53da57243512a62ccd9164969d69a616b50ff4bc4a6fe7a6fc3634f2d',
 'team config init/json/missing': 'ec61e69a2071684446d63ca7f3e396c08b49dff19ad3cba9b8bd46d2ed6494ec',
 'team config init/json/malformed': 'ec61e69a2071684446d63ca7f3e396c08b49dff19ad3cba9b8bd46d2ed6494ec',
 'team config init/json/oversized': 'ec61e69a2071684446d63ca7f3e396c08b49dff19ad3cba9b8bd46d2ed6494ec',
 'team doctor/text/help': '5191bdfdacc3884d9c9257a3be95786642a9c2894a83679c971dc8b6a19569f0',
 'team doctor/text/missing': '209bbb280f78b966ae6b85182af89972b7c4edd42c42bfab9900c562ef062510',
 'team doctor/text/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team doctor/text/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team doctor/json/help': '5191bdfdacc3884d9c9257a3be95786642a9c2894a83679c971dc8b6a19569f0',
 'team doctor/json/missing': '209bbb280f78b966ae6b85182af89972b7c4edd42c42bfab9900c562ef062510',
 'team doctor/json/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team doctor/json/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team hosts/text/help': 'ea128a09849823afc6ef51c2c1d89bb8c8259c33c17ca747c3218827b82825d8',
 'team hosts/text/missing': 'df79db9dc85f1132b0ac289735b2dd43d0a744a8be9cf1e6f1b71938d367a3f1',
 'team hosts/text/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team hosts/text/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team hosts/json/help': 'ea128a09849823afc6ef51c2c1d89bb8c8259c33c17ca747c3218827b82825d8',
 'team hosts/json/missing': '33cc3012e3b7f19fad41919efdcfc3415fd09f9798f67222a3f35b397bf84be8',
 'team hosts/json/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team hosts/json/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team claim/text/help': '4578aacde9218e0110b89f47bfa0811fd9286538fd1e0c968e636dbebde975ca',
 'team claim/text/missing': '5ecb6c970fff72df07457c849e53497a1d24982d3145c85755da71a7226571e2',
 'team claim/text/malformed': '5ecb6c970fff72df07457c849e53497a1d24982d3145c85755da71a7226571e2',
 'team claim/text/oversized': '5ecb6c970fff72df07457c849e53497a1d24982d3145c85755da71a7226571e2',
 'team claim/json/help': '4578aacde9218e0110b89f47bfa0811fd9286538fd1e0c968e636dbebde975ca',
 'team claim/json/missing': '5ecb6c970fff72df07457c849e53497a1d24982d3145c85755da71a7226571e2',
 'team claim/json/malformed': '5ecb6c970fff72df07457c849e53497a1d24982d3145c85755da71a7226571e2',
 'team claim/json/oversized': '5ecb6c970fff72df07457c849e53497a1d24982d3145c85755da71a7226571e2',
 'team renew/text/help': 'b1f57912384f6c799891bdae6939ac9b1dc35db2fc3522ab7e014f98d9013a3d',
 'team renew/text/missing': '9b68c5adcb8490359dc7623d01b43b835ea8c5b6123b39021184a7f7e54cba84',
 'team renew/text/malformed': '9b68c5adcb8490359dc7623d01b43b835ea8c5b6123b39021184a7f7e54cba84',
 'team renew/text/oversized': '9b68c5adcb8490359dc7623d01b43b835ea8c5b6123b39021184a7f7e54cba84',
 'team renew/json/help': 'b1f57912384f6c799891bdae6939ac9b1dc35db2fc3522ab7e014f98d9013a3d',
 'team renew/json/missing': '9b68c5adcb8490359dc7623d01b43b835ea8c5b6123b39021184a7f7e54cba84',
 'team renew/json/malformed': '9b68c5adcb8490359dc7623d01b43b835ea8c5b6123b39021184a7f7e54cba84',
 'team renew/json/oversized': '9b68c5adcb8490359dc7623d01b43b835ea8c5b6123b39021184a7f7e54cba84',
 'team transfer/text/help': '676ec828449ce575a2202d8c9ac8aa6c75aaa108fe36e41d730a1680cfa4f1e5',
 'team transfer/text/missing': 'aae747bb3c9fc68a52894a0ecda79b2c0ad3fdda9b4f423c142bff9ca02a18a1',
 'team transfer/text/malformed': 'aae747bb3c9fc68a52894a0ecda79b2c0ad3fdda9b4f423c142bff9ca02a18a1',
 'team transfer/text/oversized': 'aae747bb3c9fc68a52894a0ecda79b2c0ad3fdda9b4f423c142bff9ca02a18a1',
 'team transfer/json/help': '676ec828449ce575a2202d8c9ac8aa6c75aaa108fe36e41d730a1680cfa4f1e5',
 'team transfer/json/missing': 'aae747bb3c9fc68a52894a0ecda79b2c0ad3fdda9b4f423c142bff9ca02a18a1',
 'team transfer/json/malformed': 'aae747bb3c9fc68a52894a0ecda79b2c0ad3fdda9b4f423c142bff9ca02a18a1',
 'team transfer/json/oversized': 'aae747bb3c9fc68a52894a0ecda79b2c0ad3fdda9b4f423c142bff9ca02a18a1',
 'team release/text/help': '197650cd40e3c45cec03e0b1fdfada3fcdf9a26bf98753b532d092921658e052',
 'team release/text/missing': '6c844d2584f548617e41bb4e2b3d6092d64db8c73a55f9637ace7d64eb97986e',
 'team release/text/malformed': '6c844d2584f548617e41bb4e2b3d6092d64db8c73a55f9637ace7d64eb97986e',
 'team release/text/oversized': '6c844d2584f548617e41bb4e2b3d6092d64db8c73a55f9637ace7d64eb97986e',
 'team release/json/help': '197650cd40e3c45cec03e0b1fdfada3fcdf9a26bf98753b532d092921658e052',
 'team release/json/missing': '6c844d2584f548617e41bb4e2b3d6092d64db8c73a55f9637ace7d64eb97986e',
 'team release/json/malformed': '6c844d2584f548617e41bb4e2b3d6092d64db8c73a55f9637ace7d64eb97986e',
 'team release/json/oversized': '6c844d2584f548617e41bb4e2b3d6092d64db8c73a55f9637ace7d64eb97986e',
 'team gc/text/help': '71ac5ca8981dd700b3efbe9eb22c81ac56c7ff468576a6711a55d404896f2e4f',
 'team gc/text/missing': '5eb8c567de2eb92345f530cf1160036829b0919addee75dc96304eab662df0e7',
 'team gc/text/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team gc/text/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team gc/json/help': '71ac5ca8981dd700b3efbe9eb22c81ac56c7ff468576a6711a55d404896f2e4f',
 'team gc/json/missing': '79dabe090244f0e5101e4d6859741a34fe23d9d55a6c4680922d541a26ffc493',
 'team gc/json/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team gc/json/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team list/text/help': 'abd3aba9b36117f34b747940a15d2eeeb4791748159df379546d5df52d2a059a',
 'team list/text/missing': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'team list/text/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team list/text/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team list/json/help': 'abd3aba9b36117f34b747940a15d2eeeb4791748159df379546d5df52d2a059a',
 'team list/json/missing': '696707cc008c96ae104ba2c82b8d667461f7623bd9a350172e9f8eb26db7dc16',
 'team list/json/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team list/json/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team status/text/help': 'fe2053ab3b01cd9f9ab84ca1d6891e3748de56d35f4c1fd8e2e013d429a86bcc',
 'team status/text/missing': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'team status/text/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team status/text/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team status/json/help': 'fe2053ab3b01cd9f9ab84ca1d6891e3748de56d35f4c1fd8e2e013d429a86bcc',
 'team status/json/missing': 'bff194c94f28068577e8a0b7356ac5175fba7b424f7873dfcde0f83bf71d66eb',
 'team status/json/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team status/json/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team metrics/text/help': 'e06cb0bf818f66eec0312a80180027429f86c870aeb8ea69a102245ad02f5f44',
 'team metrics/text/missing': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'team metrics/text/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team metrics/text/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'team metrics/json/help': 'e06cb0bf818f66eec0312a80180027429f86c870aeb8ea69a102245ad02f5f44',
 'team metrics/json/missing': '30ea619876869dae6e295c09614f4ae7b793e207f3134b447870b60d3f828332',
 'team metrics/json/malformed': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'team metrics/json/oversized': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'msg write/text/help': '938781c63858fd3f2bc2358317ed1221f4a7692ae86fa8445e35536a8c7d947a',
 'msg write/text/missing': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg write/text/malformed': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg write/text/oversized': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg write/json/help': '938781c63858fd3f2bc2358317ed1221f4a7692ae86fa8445e35536a8c7d947a',
 'msg write/json/missing': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg write/json/malformed': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg write/json/oversized': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg read/text/help': '580b9b0cb4f35b03388700e149f9f1629cb7d2856685f70533da509ae5192319',
 'msg read/text/missing': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg read/text/malformed': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg read/text/oversized': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg read/json/help': '580b9b0cb4f35b03388700e149f9f1629cb7d2856685f70533da509ae5192319',
 'msg read/json/missing': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg read/json/malformed': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg read/json/oversized': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg verify/text/help': '49071d3909cece71907ef0c70418db3c0f6e7c3f66cbd6a4b58b15d9f0eb669c',
 'msg verify/text/missing': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg verify/text/malformed': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg verify/text/oversized': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg verify/json/help': '49071d3909cece71907ef0c70418db3c0f6e7c3f66cbd6a4b58b15d9f0eb669c',
 'msg verify/json/missing': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg verify/json/malformed': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20',
 'msg verify/json/oversized': 'a51bcbc3b21b43ea958abc025b9f0a2361fcdca80e3f7a7c9b13c64f74120a20'}


# UX-31/32 and O65 change only list/audit help. UX-33 adds fixed diagnostics
# when a structurally known command is missing required arguments, including
# when an unknown token or oversized workspace accompanies that same refusal.
# Keep the pre-change bytes above; pin each intended replacement separately.
CLI_UX_GOLDENS = {
    **{"team queue " + verb + "/" + mode + "/" + case: digest
       for verb, digest in {
           "add": "0593d64168bd09e4f1e7d3a22cb1eeff3a2eebc64abfcb5abf6dcd29ef4d2b5c",
           "claim": "6abaf5b6af3adf6de384c942c8ee38f045819e9f2676de98beb1deb187c876c2",
           "release": "042a10c48eafc656aae2a47086e0b751c6bfb7f53753ae3139079754e0b21421",
           "done": "bcb1c6e4bd6753aac560948054a2a2b4f82ebf98a008a48d46a5284958cde373",
           "unclaim": "0020b3faa0659243c9ad11538333a86c504de3bc6283f1a44c57abecce9186a5",
       }.items() for mode in ("text", "json") for case in ("missing", "malformed", "oversized")},
    **{"team queue " + verb + "/" + mode + "/help": digest
       for verb, digest in {
           "list": "77a430891f2264cef34b496f167d69d41f5c891a20243abff1dec9853053bedd",
           "audit": "08eda48b73fae65a126f915decbe5ef8293e665d2fa13860e6c6433f0098da9a",
       }.items() for mode in ("text", "json")},
}


@pytest.mark.parametrize("cwd_length", [1, 120], ids=["short-cwd", "long-cwd"])
def test_cli_path_byte_goldens(workspace, tmp_path, capsys, monkeypatch, cwd_length):
    monkeypatch.setenv("COLUMNS", "80")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("PYTHON_COLORS", "0")
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.setattr(team_profile, "pathlookup", SimpleNamespace(
        which=lambda name, **options: "/host/" + name if name in ("codex", "claude") else None))
    working_directory = tmp_path / ("w" * cwd_length)
    working_directory.mkdir()
    original = os.getcwd()
    try:
        os.chdir(working_directory)
        _check_cli_path_byte_goldens(tmp_path, capsys)
    finally:
        os.chdir(original)


def _check_cli_path_byte_goldens(tmp_path, capsys):
    import re

    observations = {}
    for path in CLI_PATHS:
        for mode in ("text", "json"):
            for case, suffix in (("help", ["--help"]), ("missing", []),
                                 ("malformed", ["--unknown=private-value"]),
                                 ("oversized", ["--workspace", "x" * 32769])):
                argv = ["--workspace", str(tmp_path / "missing"), *path.split()]
                if mode == "json":
                    argv.append("--json")
                try:
                    code = main(argv + suffix)
                except SystemExit as error:
                    code = error.code
                captured = capsys.readouterr()
                stderr = _canonical_cli_os_error(captured.err)
                if case == "oversized":
                    # Normalize only the absolute cwd within this exact filename,
                    # before ROOT substitution can rewrite part of that prefix.
                    filename = str(Path.cwd() / suffix[-1])
                    stderr = stderr.replace(filename, "CWD/" + suffix[-1])
                streams = [re.sub(r'"checked_at": "[^"]+"', '"checked_at": "CLOCK"',
                                  stream.replace(str(tmp_path), "ROOT").replace("optional arguments:\n", "options:\n"))
                           for stream in (captured.out, stderr)]
                observations[path + "/" + mode + "/" + case] = [code, *streams]
    actual = {key: hashlib.sha256(json.dumps(value, ensure_ascii=True).encode()).hexdigest()
              for key, value in observations.items()}
    assert actual == {**CLI_BYTE_GOLDENS, **CLI_UX_GOLDENS}


def _canonical_cli_os_error(stream, *, diagnostic=None):
    if diagnostic is None:
        diagnostic = f"[Errno {errno.ENAMETOOLONG}] {os.strerror(errno.ENAMETOOLONG)}: "
    return stream.replace(diagnostic, "[Errno 36] File name too long: ")


@pytest.mark.parametrize("diagnostic", ["[Errno 36] File name too long: ",
                                      "[Errno 63] File name too long: ",
                                      "[Errno 63] Nom de fichier trop long: "],
                         ids=["linux", "macos", "translated"])
def test_golden_os_diagnostic_is_platform_and_locale_independent(diagnostic):
    suffix = "'CWD/" + "x" * 32769 + "'\n"
    assert _canonical_cli_os_error("Error: " + diagnostic + suffix, diagnostic=diagnostic) == (
        "Error: [Errno 36] File name too long: " + suffix)


@pytest.mark.parametrize("words", [("team", "queue", "list"),
                                  ("team", "model", "--unknown=private-value"),
                                  ("msg", "read", "a" * 64)], ids=["queue", "model", "msg"])
def test_single_pass_argv_matches_list(workspace, capsys, monkeypatch, words):
    monkeypatch.setattr(team_queue, "time", SimpleNamespace(time=lambda: 100))
    arguments = ["--workspace", str(workspace), *words]
    expected_code = main(arguments)
    expected = capsys.readouterr()
    actual_code = main(iter(arguments))
    actual = capsys.readouterr()
    assert (actual_code, actual.out, actual.err) == (expected_code, expected.out, expected.err)


def test_hook_fast_path_does_not_import_message_policy(tmp_path):
    root = Path(__file__).resolve().parents[3]
    script = """import contextlib, io, json, sys
from aegis_cli import cli
out, err = io.StringIO(), io.StringIO()
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
    code = cli.main(['hook', 'run', 'pre-tool', '--host', 'claude-code'])
print(json.dumps({'code': code, 'stdout': out.getvalue(), 'stderr': err.getvalue(),
                  'msg_loaded': 'aegis_cli.msg' in sys.modules, 'source': cli.__file__}))
"""
    process = subprocess.run([sys.executable, "-c", script], cwd=tmp_path,
                             env={**os.environ, "PYTHONPATH": str(root)}, input="{}",
                             capture_output=True, text=True, timeout=15)
    assert process.returncode == 0 and process.stderr == ""
    observed = json.loads(process.stdout)
    assert Path(observed.pop("source")) == root / "aegis_cli/cli.py"
    assert observed == {"code": 0, "stdout": "", "stderr": "", "msg_loaded": False}


def test_queue_adapter_public_refusal_matches_entry_point(capsys):
    from aegis_cli.team_queue import run_queue

    assert run_queue(SimpleNamespace(queue_action=None)) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    result = json.loads(captured.out)
    assert result["schema"] == "aegis.team.queue.usage/v1"
    assert result["reason"] == "invalid_arguments"


QUEUE_FLOW_GOLDENS = {'list-empty': '19b5c8a55c4e8d0b28dff7ce340f919ca7221af0e6ca1fb23b82ff73b0811eaf',
 'add-malformed': '0986a7112917571703c5c62cfa10aceeb8b64e42ec2687c5211706f0f7d9091a',
 'add-oversized': '0986a7112917571703c5c62cfa10aceeb8b64e42ec2687c5211706f0f7d9091a',
 'add': '0d368f6c2c750d75c41c51eba26edb617962905d6053ee8112635fcc9fe106fa',
 'add-duplicate': 'd2522f7ca2d46e5fa8dee2fa86b068130d317d5f86832ec43eb49d36d17d2ce5',
 'claim-missing': '85cf7a4a7babacd5224dc12334cbb6302f60f6bc33d3a3667f4cc74b1f58656d',
 'claim-stale': 'd14544c058b8556442703607c63beda479c1dbb4b959c0bec38ff1a1d52b78cc',
 'claim': '329151d95c85e73d61578e74cfe1c52e7f473c157bb045f24c4d6b7df4dd1665',
 'unclaim-running': '8df21067e1acf192e8552d2394a91169d6bfd02ca51fc78202fa25b6e9ae1a40',
 'release': 'a332c486d97e886e7c2318c7ab19583d42db77078c82ff2fee81c55a773b7a0b',
 'claim-retry': '370e22efa0dc89aea9d37b88d85ef23111979fd57e47c31bfb981aecda30a846',
 'unclaim': '003251bd01a1e61bd0a9baaa55c61225d4dcf73838e9416eb439c37cd4188e43',
 'claim-again': 'fdbafd1f9ac85839cd7a39310052edad2ec243000f6331572e50c147a5117cd0',
 'audit': 'f61f68bcecb5984798c312cade0f88543f342e1d56fede22b34096f495a56d9d',
 'list': '46203e5bb51d1e9d06d5258180a89483bf7dbf2c46b39a99364bf67ff8060eba',
 'done': 'c62ee4762ca8916ce8de3549a008b9a0ce99d6b55fb83dd215cbc22fe8bc9f8f',
 'list-done': 'cfc2339579074f1ecd61ebd3bc0d5ad29675a1dad9b0ec1bddf649eab4d03c50',
 'compact': 'd9d28429080e7e43bd5d4645d1bb79787392742f1a827e83529e3d77346277ef',
 'compact-retry': '876c4a32331258f56583db4ca56cc30f947592ede7c16ab53060d018d2ff6dca'}


def test_queue_flow_byte_goldens(workspace, capsys, monkeypatch):
    from itertools import count

    revisions = count(1)
    randomness = SimpleNamespace(token_hex=lambda size: format(next(revisions), "0" + str(size * 2) + "x"))
    monkeypatch.setattr(team_queue, "secrets", randomness)
    monkeypatch.setattr(team_claims, "secrets", randomness)
    monkeypatch.setattr(team_queue, "time", SimpleNamespace(time=lambda: 100))
    value = json.dumps({"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []})
    observations = {}
    revision = "0" * 64
    for key, arguments in (
        ("list-empty", ["list"]), ("add-malformed", ["add", "--item", "["]),
        ("add-oversized", ["add", "--item", " " * (team_queue.MAX_BYTES + 1)]),
        ("add", ["add", "--item", value]), ("add-duplicate", ["add", "--item", value]),
        ("claim-missing", ["claim", "NONE", "--expect", revision, "--lane", "writer"]),
        ("claim-stale", ["claim", "ONE", "--expect", revision, "--lane", "writer"]),
        ("claim", ["claim", "ONE", "--expect", "REVISION", "--lane", "writer"]),
        ("unclaim-running", ["unclaim", "ONE", "--expect", "REVISION", "--lane", "writer"]),
        ("release", ["release", "ONE", "--expect", "REVISION", "--lane", "writer"]),
        ("claim-retry", ["claim", "ONE", "--expect", "REVISION", "--lane", "writer"]),
        ("unclaim", ["unclaim", "ONE", "--expect", "REVISION", "--lane", "writer", "--writer-stopped"]),
        ("claim-again", ["claim", "ONE", "--expect", "REVISION", "--lane", "writer"]),
        ("audit", ["audit"]), ("list", ["list"]),
        ("done", ["done", "ONE", "--expect", "REVISION", "--lane", "writer"]),
        ("list-done", ["list", "--include-done"]), ("compact", ["compact"]),
        ("compact-retry", ["compact"]),
    ):
        arguments = [revision if arg == "REVISION" else arg for arg in arguments]
        code = main(["--workspace", str(workspace), "team", "queue", *arguments])
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        if "item" in result:
            revision = result["item"]["revision"]
            visible = team_queue.list(workspace, include_done=True)["items"]
            stored = next(row for row in visible if row["id"] == result["item"]["id"])
            assert stored["revision"] == revision
        observations[key] = [code, captured.out, captured.err]
    for key, observation in observations.items():
        _assert_queue_flow_golden(key, observation)


def _assert_queue_flow_golden(key, observation):
    import re

    def normalize(stream):
        stream = re.sub(r'"checked_at": "[^"]+"', '"checked_at": "CLOCK"', stream)
        return stream

    code, stdout, stderr = observation
    actual = hashlib.sha256(json.dumps([code, normalize(stdout), stderr]).encode()).hexdigest()
    assert actual == QUEUE_FLOW_GOLDENS[key], key


def test_queue_flow_golden_rejects_wrong_fingerprint(workspace, capsys, monkeypatch):
    monkeypatch.setattr(team_queue, "time", SimpleNamespace(time=lambda: 100))
    code = main(["--workspace", str(workspace), "team", "queue", "list"])
    captured = capsys.readouterr()
    observation = [code, captured.out, captured.err]
    _assert_queue_flow_golden("list-empty", observation)
    wrong = json.loads(captured.out)
    wrong["claimable_fingerprint"] = "0" * 64
    observation[1] = json.dumps(wrong, indent=2) + "\n"
    with pytest.raises(AssertionError, match="list-empty"):
        _assert_queue_flow_golden("list-empty", observation)


def test_queue_flow_golden_rejects_wrong_revision(workspace, capsys, monkeypatch):
    monkeypatch.setattr(team_queue, "time", SimpleNamespace(time=lambda: 100))
    monkeypatch.setattr(team_queue, "secrets", SimpleNamespace(token_hex=lambda size: "0" * 63 + "1"))
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    code = main(["--workspace", str(workspace), "team", "queue", "add", "--item", json.dumps(value)])
    captured = capsys.readouterr()
    observation = [code, captured.out, captured.err]
    _assert_queue_flow_golden("add", observation)
    wrong = json.loads(captured.out)
    wrong["item"]["revision"] = "0" * 64
    observation[1] = json.dumps(wrong, indent=2) + "\n"
    with pytest.raises(AssertionError, match="add"):
        _assert_queue_flow_golden("add", observation)


@pytest.fixture
def workspace(tmp_path):
    if not team_queue.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    if shutil.which("git") is None:
        pytest.skip("requires git")
    root = tmp_path / "workspace"
    (root / ".aegis" / "rules").mkdir(parents=True)
    (root / ".aegis" / "team.json").write_text(
        json.dumps({"v": 1, "lanes": {"writer": ["src/**"]}}), encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    home = tmp_path / "home"
    home.mkdir()
    # The autouse hermetic_environment_and_mcp_isolation fixture restores this
    # environment. Explicit --workspace keeps cwd unchanged throughout.
    os.environ.update({"HOME": str(home), "USERPROFILE": str(home)})
    return root


def run(capsys, root, *arguments):
    try:
        code = main(["--workspace", str(root), "team", "queue", *arguments, "--json"])
    except SystemExit as error:
        code = error.code
    captured = capsys.readouterr()
    assert captured.err == ""
    return code, json.loads(captured.out)


@pytest.mark.parametrize("arguments,category,names,verb", [
    (["add"], "missing_required", ["--item"], "add"),
    (["claim", "private-value"], "missing_required", ["--expect", "--lane"], "claim"),
    (["claim", "private-value", "--lane", "writer"], "missing_required", ["--expect"], "claim"),
    (["claim", "--expect", "a" * 64, "--lane", "writer"], "missing_required", ["ITEM"], "claim"),
    (["claim", "private-value", "--expect", "a" * 64, "--lane"], "missing_value", ["--lane"], "claim"),
    (["claim", "private-value", "--expect", "a" * 64, "--lane", "writer", "--ttl", "token=private-value\n--expect"],
     "invalid_value", ["--ttl"], "claim"),
    (["list", "--view", "token=x\n"], "invalid_value", ["--view"], "list"),
    (["list", "--view", "private-value" * 100], "limit_exceeded", ["--view"], "list"),
    (["audit", "--view", "private-value" * 100], "limit_exceeded", ["--view"], "audit"),
    (["list", "--capability", "private-value" * 100], "limit_exceeded", ["--capability"], "list"),
    (["list", *[word for _ in range(129) for word in ("--capability", "private-value")]],
     "limit_exceeded", ["--capability"], "list"),
    (["release", "private-value"], "missing_required", ["--expect"], "release"),
    (["done", "private-value"], "missing_required", ["--expect"], "done"),
    (["unclaim", "private-value"], "missing_required", ["--expect", "--lane"], "unclaim"),
])
def test_queue_parser_actionable_safe_categories(capsys, arguments, category, names, verb):
    for _ in range(2):
        code, payload = run(capsys, ".", *arguments)
        assert code == 2 and payload["reason"] == "invalid_arguments"
        assert payload["argument_error"] == {"category": category, "arguments": names,
                                              "help_command": "aegis team queue " + verb + " --help"}
        assert "private-value" not in json.dumps(payload)
        assert "token=x" not in json.dumps(payload)
    assert main(["team", "queue", verb, "--help"]) == 0
    assert "usage:" in capsys.readouterr().out


def test_queue_parser_without_invocation_policy_uses_fixed_help(capsys):
    from aegis_cli.cli import _build_parser

    parser = _build_parser(prog="token=private-value\n--expect")
    with pytest.raises(SystemExit) as error:
        parser.parse_args(["team", "queue", "claim", "private-value", "--lane", "writer"])
    assert error.value.code == 2
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert captured.err == "" and "private-value" not in captured.out
    assert payload["argument_error"] == {"category": "missing_required", "arguments": ["--expect"],
                                          "help_command": "aegis team queue claim --help"}


def test_queue_parser_concurrent_processes_keep_diagnostics_local():
    from concurrent.futures import ThreadPoolExecutor

    commands = [["team", "queue", "claim", "private-value", "--lane", "writer"],
                ["team", "queue", "list", "--view", "token=x"],
                ["team", "queue", "audit", "--view", "findings", "--help"]]
    root = Path(__file__).resolve().parents[3]
    def invoke(words):
        return subprocess.run([sys.executable, "-m", "aegis_cli", *words], cwd=root,
                              capture_output=True, text=True, timeout=30)
    with ThreadPoolExecutor(max_workers=3) as workers:
        futures = [workers.submit(invoke, words) for words in commands]
        results = [future.result(timeout=35) for future in futures]
    for result, category, names in zip(results, ("missing_required", "invalid_value"), (["--expect"], ["--view"])):
        assert result.returncode == 2 and result.stderr == ""
        assert "private-value" not in result.stdout and "token=x" not in result.stdout
        diagnostic = json.loads(result.stdout)["argument_error"]
        assert diagnostic["category"] == category and diagnostic["arguments"] == names
    assert results[2].returncode == 0 and results[2].stderr == "" and "--view" in results[2].stdout


@pytest.mark.parametrize("arguments", [["list", "--unknown=token=private-value"],
                                       ["private-value\n--expect"],
                                       ["list", "--workspace", "../private-value"]])
def test_queue_parser_unknown_input_stays_generic(capsys, arguments):
    code, payload = run(capsys, ".", *arguments)
    assert code == 2 and payload["reason"] == "invalid_arguments"
    assert "argument_error" not in payload
    assert "private-value" not in json.dumps(payload)


def test_cli_partial_views_and_capability_help(workspace, capsys):
    code, added = run(capsys, workspace, "add", "--item", json.dumps({
        "id": "ONE", "title": "Queue work", "paths": ["src/**"], "capabilities": [],
        "hold": "Await decision", "hold_until": [{"kind": "lease_free", "paths": ["src/**"]}]}))
    assert code == 0
    code, full = run(capsys, workspace, "list")
    code, small = run(capsys, workspace, "list", "--view", "fingerprint")
    assert code == 0 and "items" not in small
    assert small["claimable_fingerprint"] == full["claimable_fingerprint"]
    code, findings = run(capsys, workspace, "audit", "--view", "findings")
    assert code == 0 and "items" not in findings
    assert findings["affected_items"][0]["revision"] == added["item"]["revision"]
    code, complete = run(capsys, workspace, "audit")
    assert complete["findings"] == findings["findings"] and "items" in complete
    assert main(["team", "queue", "list", "--help"]) == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert "list items whose requirements are all satisfied" in help_text


@pytest.mark.parametrize("state,effective,expired", [("active", "claimed", False),
                                                    ("expired", "queued", True),
                                                    ("completed", "done", False)])
def test_cli_findings_pointer_displays_every_affected_item(workspace, capsys, monkeypatch, state, effective, expired):
    root = workspace
    value = {"id": "ONE", "title": "Legacy work", "paths": ["src/**"], "capabilities": []}
    added = team_queue.add(root, value, now=100)
    assert added["exit_code"] == 0
    claimed = team_queue.claim(root, "ONE", expect=added["item"]["revision"], lane="writer",
                               branch="lane/writer", ttl_s=10, now=101)
    assert claimed["exit_code"] == 0
    if state == "completed":
        assert team_queue.done(root, "ONE", expect=claimed["item"]["revision"], lane="writer", now=102)["exit_code"] == 0
    path = root / ".aegis/state/team-queue.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["items"]["ONE"]["branch"] = "refs/heads/refs/tags/legacy"
    path.write_text(json.dumps(document), encoding="utf-8")
    original = path.read_bytes()
    moment = 112 if state == "expired" else 103
    monkeypatch.setattr(team_queue, "time", SimpleNamespace(time=lambda: moment))
    command = "aegis team queue list --include-done --view full --json"
    for _ in range(2):
        code, findings = run(capsys, root, "audit", "--view", "findings")
        assert code == 0 and any(row["code"] == "CLAIM-BRANCH-UNSUPPORTED" for row in findings["findings"])
        assert findings["next_action"] == "Run " + command + " and read full constraints before changing holds or work."
        code, inspected = run(capsys, root, *command.split()[3:])
        assert code == 0
        full_item = next(row for row in inspected["items"] if row["id"] == "ONE")
        assert full_item["state"] == effective and full_item["lease_expired"] is expired
        assert findings["affected_items"] == [{key: full_item[key]
            for key in ("id", "revision", "lane", "state", "lease_expired", "expires_at")}]
    assert path.read_bytes() == original


def test_cli_unclaim_releases_lane_lease_and_preserves_refusal_envelope(workspace, capsys):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    code, added = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 0
    code, claimed = run(capsys, workspace, "claim", "ONE", "--expect", added["item"]["revision"], "--lane", "writer")
    assert code == 0
    lease = team.claim(workspace, "writer", ["src/**"])
    revision = claimed["item"]["revision"]
    code, refused = run(capsys, workspace, "unclaim", "ONE", "--expect", revision, "--lane", "writer")
    assert code == 1 and refused["reason"] == "writer_not_stopped"
    code, refused = run(capsys, workspace, "unclaim", "ONE", "--expect", revision, "--lane", "writer", "--writer-stopped", "--reason", "token=private-value")
    assert code == 2 and refused["reason"] == "credential_like_text"
    assert "private-value" not in json.dumps(refused)
    code, released = run(capsys, workspace, "unclaim", "ONE", "--expect", revision, "--lane", "writer", "--writer-stopped", "--reason", "Waiting for review")
    assert code == 0 and released["schema"] == "aegis.team.queue.unclaim/v1"
    assert released["item"]["state"] == "queued" and released["released_lease_ids"] == [lease.oid]
    assert team.read_leases(workspace).get("writer") is None
    assert run(capsys, workspace, "unclaim", "ONE", "--expect", revision, "--lane", "writer", "--writer-stopped")[0] == 1


def test_cli_unclaim_live_binding_defeats_stop_acknowledgement(workspace, capsys, monkeypatch):
    if not binding.descriptor_supported():
        pytest.skip("requires Linux process identity and confined storage")
    home = workspace.parent / "passwd-home"
    (home / ".config/aegis").mkdir(parents=True)
    monkeypatch.setattr(team_claims, "pwd", SimpleNamespace(getpwuid=lambda uid: SimpleNamespace(pw_dir=str(home))))
    added = team_queue.add(workspace, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []})
    claimed = team_queue.claim(workspace, "ONE", expect=added["item"]["revision"], lane="writer")
    lease = team.claim(workspace, "writer", ["src/**"])
    assert binding.bind(str(home), workspace, "writer", os.getpid())["status"] == "ok"
    revision = claimed["item"]["revision"]
    path = workspace / ".aegis/state/team-queue.json"
    before = path.read_bytes()
    for flags in ([], ["--writer-stopped"], ["--writer-stopped"]):
        code, result = run(capsys, workspace, "unclaim", "ONE", "--expect", revision, "--lane", "writer", *flags)
        assert code == 1 and result["reason"] == "writer_live", result
        assert result["schema"] == "aegis.team.queue.unclaim/v1" and "Stop the bound writer" in result["next_action"]
        assert path.read_bytes() == before and team.read_leases(workspace).get("writer").oid == lease.oid


def test_queue_cli_lifecycle_and_core_parity(workspace, capsys):
    item = {"id": "ONE", "title": "Core work", "paths": ["src/**"], "capabilities": ["core"]}
    code, added = run(capsys, workspace, "add", "--item", json.dumps(item))
    assert code == 0 and added["schema"] == "aegis.team.queue.add/v1"
    revision = added["item"]["revision"]
    code, claimed = run(capsys, workspace, "claim", "ONE", "--expect", revision,
                        "--lane", "writer", "--capability", "core")
    assert code == 0 and claimed["item"]["label"] == "writer [ONE: Core work]"
    code, listed = run(capsys, workspace, "list")
    assert code == 0
    expected = team_queue.list(workspace)
    listed.pop("checked_at")
    expected.pop("checked_at")
    assert listed == expected
    assert run(capsys, workspace, "claim", "ONE", "--expect", revision,
               "--lane", "writer", "--capability", "core")[0] == 1
    code, released = run(capsys, workspace, "release", "ONE", "--expect", claimed["item"]["revision"], "--lane", "writer")
    assert code == 0
    code, claimed = run(capsys, workspace, "claim", "ONE", "--expect", released["item"]["revision"],
                        "--lane", "writer", "--capability", "core", "--ttl", "60")
    assert code == 0
    code, completed = run(capsys, workspace, "done", "ONE", "--expect", claimed["item"]["revision"], "--lane", "writer")
    assert code == 0 and completed["item"]["state"] == "done"
    code, audited = run(capsys, workspace, "audit")
    assert code == 0 and audited["findings"] == []


def test_live_queue_claim_remains_ready_after_cli_repository_claim(workspace, capsys):
    value = {"id": "ONE", "title": "Core work", "paths": ["src/**"], "capabilities": [],
             "hold_until": [{"kind": "lease_free", "paths": ["src/**"]}]}
    code, added = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 0
    code, claimed = run(capsys, workspace, "claim", "ONE", "--expect", added["item"]["revision"],
                        "--lane", "writer")
    assert code == 0
    assert main(["--workspace", str(workspace), "team", "claim", "writer", "--paths", "src/**", "--json"]) == 0
    captured = capsys.readouterr()
    assert captured.err == "" and json.loads(captured.out)["status"] == "claimed"
    code, listed = run(capsys, workspace, "list")
    assert code == 0 and listed["items"][0]["conditions_met"] is True
    assert listed["items"][0]["blockers"] == []
    assert "Wait for" not in json.dumps(listed)


@pytest.mark.parametrize("arguments", [
    (), ("unknown", "token=private-value"), ("add", "--item", "token=private-value"),
    ("add", "--item", "{}", "--unknown", "token=private-value"),
    ("claim", "ONE", "--expect", "token=private-value", "--lane", "writer"),
    ("claim", "ONE", "--expect", "0" * 64, "--lane", "writer", "--ttl", "secret"),
    ("list", "--capability", "token=private-value"),
])
def test_queue_usage_refuses_without_echo(workspace, capsys, arguments):
    code, result = run(capsys, workspace, *arguments)
    assert code == 2 and result["refused"] and result["reason"] in ("invalid_arguments", "invalid_item")
    assert result["next_action"]
    assert "private-value" not in json.dumps(result)


@pytest.mark.parametrize("verb", ["list", "audit", "compact"])
def test_cli_unsupported_platform_uses_refusal_envelope(tmp_path, monkeypatch, capsys, verb):
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    monkeypatch.setattr(team_queue, "descriptor_supported", lambda: False)
    code, result = run(capsys, tmp_path, verb)
    assert code == 1 and result["reason"] == "unsupported_platform"


def test_queue_workspace_failure_does_not_echo_path(tmp_path, capsys):
    code, result = run(capsys, tmp_path, "list", "--workspace", "token=private-value/missing")
    assert code == 1 and result["refused"] and result["next_action"]
    assert "private-value" not in json.dumps(result)


@pytest.mark.parametrize("mode", ("json", "text"))
def test_refused_lane_claim_exposes_anchor_next_action_in_subprocess(workspace, mode):
    (workspace / "pyproject.toml").write_text("# root file\n", encoding="utf-8")
    team.claim(workspace, "docs", ["/docs/"], owner="owner")
    source = Path(__file__).resolve().parents[3]
    environment = dict(os.environ, PYTHONPATH=str(source))
    arguments = [sys.executable, "-m", "aegis_cli", "team", "claim", "writer",
                 "--workspace", str(workspace), "--paths", "pyproject.toml"]
    if mode == "json":
        arguments.append("--json")
    result = subprocess.run(arguments, cwd=workspace, env=environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 1, (result.stdout, result.stderr)
    expected = "Retry with root-anchored lease paths: /pyproject.toml; slashless paths cover every depth."
    if mode == "json":
        payload = json.loads(result.stdout)
        assert payload["reason"] == "overlap"
        assert payload["next_action"] == expected
        assert result.stderr == ""
    else:
        assert result.stdout == ""
        assert expected in result.stderr

@pytest.mark.parametrize("prefix", [("--bad=token=private-value", "team"),
                                   ("team", "--bad=token=private-value"),
                                   ("--bad", "token=private-value", "team"),
                                   ("team", "--bad", "token=private-value")])
def test_queue_ancestor_parser_refuses_without_echo(workspace, capsys, prefix):
    try:
        code = main(["--workspace", str(workspace), *prefix, "queue", "list", "--json"])
    except SystemExit as error:
        code = error.code
    captured = capsys.readouterr()
    assert code == 2 and captured.err == ""
    payload = json.loads(captured.out)
    assert payload["refused"] and payload["reason"] == "invalid_arguments"
    assert "private-value" not in captured.out


@pytest.mark.parametrize("position", [0, 1, 2, 3], ids=["root", "team", "queue", "verb"])
@pytest.mark.parametrize("options", [
    ["--unknown=token=private-value"],
    ["--unknown", "token=private-value"],
    ["--bad", "--workspace", "/ws", "--unknown=token=private-value"],
    ["--bad", "--other", "token=private-value"],
    ["--bad", "--work", "token=private-value"],
    ["--bad", "--work=token=private-value"],
    ["--=token=private-value"],
], ids=["equals", "separate", "unknown-workspace", "unknown-option", "abbreviation",
        "abbreviation-equals", "ambiguous-abbreviation"])
@pytest.mark.parametrize("model_value", [False, True], ids=["ordinary", "model-data"])
def test_queue_privacy_scope_refuses_malformed_options(capsys, position, options, model_value):
    argv = ["team", "queue", "list"]
    argv[position:position] = options
    if model_value:
        argv.extend(["--capability", "model"])
    try:
        code = main(argv)
    except SystemExit as error:
        code = error.code
    captured = capsys.readouterr()
    assert "token=private-value" not in captured.out + captured.err
    assert "private-value" not in captured.out + captured.err
    assert code == 2 and captured.err == ""
    payload = json.loads(captured.out)
    assert payload["schema"] == "aegis.team.queue.usage/v1"
    assert payload["refused"] is True and payload["reason"] == "invalid_arguments"
    assert payload["exit_code"] == 2
    assert payload["next_action"] == "Use the documented queue arguments and the revision returned by list."


@pytest.mark.parametrize("argv", [
    ["--bad", "--workspace", "/ws", "--unknown=token=private-value", "team", "queue", "list"],
    ["--bad", "--other", "token=private-value", "team", "queue", "list"],
    ["team", "--bad", "--workspace", "claim", "--leak=token=private-value", "queue", "list"],
    ["--bad", "queue", "--leak=token=private-value", "team", "queue", "list"],
    ["--bad", "queue", "--leak=token=private-value", "team", "queue", "list", "--capability", "model"],
    ["--bad", "queue", "--leak=token=private-value", "team", "queue", "list", "--capability", "msg"],
    ["--pl", "team", "queue", "unknown"],
    ["--js", "--workspace", "/tmp/ws", "team", "queue", "unknown"],
])
def test_queue_privacy_scope_reviewer_reproducers(capsys, argv):
    try:
        code = main(argv)
    except SystemExit as error:
        code = error.code
    captured = capsys.readouterr()
    assert "private-value" not in captured.out + captured.err
    assert code == 2 and captured.err == ""
    payload = json.loads(captured.out)
    assert payload["reason"] == "invalid_arguments" and payload["next_action"]


@pytest.mark.parametrize("argv", [
    ["team", "list", "queue", "--unknown=token=private-value"],
    ["--workspace", "team", "--unknown=token=private-value", "queue"],
    ["team", "--workspace", "queue", "--unknown=token=private-value"],
])
def test_queue_privacy_scope_includes_option_values_and_nonqueue_commands(capsys, argv):
    try:
        code = main(argv)
    except SystemExit as error:
        code = error.code
    captured = capsys.readouterr()
    assert "private-value" not in captured.out + captured.err
    assert code == 2 and captured.err == ""
    assert json.loads(captured.out)["reason"] == "invalid_arguments"


@pytest.mark.parametrize("argv", [
    ["--", "team", "queue", "--x=token=private-value"],
    ["team", "--", "queue", "--x=token=private-value"],
    ["--", "team", "--x=token=private-value", "queue", "list"],
    ["--", "team", "queue", "list", "--x=token=private-value"],
    ["team", "queue", "--", "list", "--x=token=private-value"],
    ["team", "queue", "list", "--", "--x=token=private-value"],
])
def test_queue_privacy_scope_includes_double_dash(capsys, argv):
    try:
        code = main(argv)
    except SystemExit as refused:
        code = refused.code
    captured = capsys.readouterr()
    assert "private-value" not in captured.out + captured.err
    assert code == 2 and captured.err == ""
    result = json.loads(captured.out)
    assert result["schema"] == "aegis.team.queue.usage/v1"
    assert result["reason"] == "invalid_arguments" and result["next_action"]


@pytest.mark.parametrize("removed", ["audit", "report", "agent"])
@pytest.mark.parametrize("position", [0, 1, 2, 3], ids=["root", "team", "queue", "verb"])
@pytest.mark.parametrize("form", ["separate", "equals"])
@pytest.mark.parametrize("separator", [False, True], ids=["ordinary", "double-dash"])
def test_queue_privacy_scope_bypasses_removed_command_pointer(capsys, removed, position, form, separator):
    options = (["--bad", removed, "--leak=token=private-value"] if form == "separate" else
               ["--bad=token=private-value", removed])
    argv = ["team", "queue", "list"]
    argv[position:position] = options
    if separator:
        argv.insert(0, "--")
    try:
        code = main(argv)
    except SystemExit as refused:
        code = refused.code
    captured = capsys.readouterr()
    assert "private-value" not in captured.out + captured.err
    assert code == 2 and captured.err == ""
    result = json.loads(captured.out)
    assert result["schema"] == "aegis.team.queue.usage/v1"
    assert result["refused"] is True and result["reason"] == "invalid_arguments"
    assert result["exit_code"] == 2 and result["next_action"]


@pytest.mark.parametrize("position", [0, 1, 2, 3], ids=["root", "team", "queue", "verb"])
@pytest.mark.parametrize("padding", ["/." * 300, "x" * 32769], ids=["components", "length"])
def test_queue_privacy_scope_bounds_merged_workspace(capsys, tmp_path, position, padding):
    argv = ["team", "queue", "list"]
    argv[position:position] = ["--workspace", str(tmp_path) + padding]
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.err == "" and str(tmp_path) not in captured.out
    payload = json.loads(captured.out)
    assert payload["reason"] == "invalid_arguments" and payload["next_action"]


@pytest.mark.parametrize("position", [0, 1, 2, 3], ids=["root", "team", "queue", "verb"])
@pytest.mark.parametrize("verb", ["list", "add", "claim"])
@pytest.mark.parametrize("invalid", ["parent", "windows-parent", "empty", "nul",
    "drive-parent", "drive-parent-only", "rooted-parent", "relative-parent"])
def test_queue_refuses_invalid_raw_workspace_before_resolution(tmp_path, monkeypatch, capsys, position, verb, invalid):
    root = tmp_path / "workspace"
    (root / ".aegis" / "rules").mkdir(parents=True)
    monkeypatch.chdir(root)
    values = {"parent": str(root) + "/../" + root.name,
              "windows-parent": str(root) + "\\..\\" + root.name,
              "empty": "", "nul": str(root) + "/\x00",
              "drive-parent": "C:..\\ws", "drive-parent-only": "C:..",
              "rooted-parent": "\\..\\ws", "relative-parent": "ws/../x"}
    argv = ["team", "queue", verb]
    if verb == "add":
        argv.extend(["--item", json.dumps({"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []})])
    elif verb == "claim":
        argv.extend(["ONE", "--expect", "0" * 64, "--lane", "writer"])
    argv[position:position] = ["--workspace", values[invalid]]
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.err == "" and str(root) not in captured.out
    result = json.loads(captured.out)
    assert result["schema"] == "aegis.team.queue.usage/v1"
    assert result["refused"] is True and result["reason"] == "invalid_arguments"
    assert result["exit_code"] == 2 and result["next_action"]
    assert not (root / ".aegis" / "state" / "team-queue.json").exists()


@pytest.mark.parametrize("position", [0, 1, 2, 3], ids=["root", "team", "queue", "verb"])
@pytest.mark.parametrize("suffix", ["/./", "/..cache"])
def test_queue_workspace_accepts_nonparent_components(workspace, capsys, position, suffix):
    (workspace / "..cache").mkdir()
    argv = ["team", "queue", "list"]
    argv[position:position] = ["--workspace", str(workspace) + suffix]
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    result = json.loads(captured.out)
    assert result["schema"] == "aegis.team.queue.list/v1" and result["refused"] is False


@pytest.mark.parametrize("field", ["title", "hold", "scope_rulings", "invariants"])
def test_secret_item_text_reaches_fixed_service_refusal(workspace, capsys, field):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    value[field] = ["token=private-value"] if field in ("scope_rulings", "invariants") else "token=private-value"
    code, result = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 2 and result["schema"] == "aegis.team.queue.add/v1"
    assert result["reason"] == "credential_like_text" and result["next_action"]
    assert "private-value" not in json.dumps(result)
    assert not (workspace / ".aegis" / "state" / "team-queue.json").exists()


@pytest.mark.parametrize("argv", [
    ["team", "claim", "model", "--paths", "src/**"],
    ["team", "claim", "model", "--paths", "queue"],
    ["team", "claim", "alpha", "--paths", "queue", "--owner", "model"],
])
def test_successful_nonqueue_parse_keeps_model_token_policy(capsys, argv):
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"error": "invalid_model_arguments"}


def test_cli_completed_filter_compact_and_retry(workspace, capsys):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    code, added = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 0
    code, claimed = run(capsys, workspace, "claim", "ONE", "--expect", added["item"]["revision"], "--lane", "writer")
    assert code == 0
    assert run(capsys, workspace, "done", "ONE", "--expect", claimed["item"]["revision"], "--lane", "writer")[0] == 0
    assert run(capsys, workspace, "list")[1]["items"] == []
    assert run(capsys, workspace, "list", "--include-done")[1]["items"][0]["id"] == "ONE"
    code, compacted = run(capsys, workspace, "compact")
    assert code == 0 and compacted["removed_count"] == 1
    assert compacted["schema"] == "aegis.team.queue.compact/v1"
    assert run(capsys, workspace, "compact")[1]["removed_count"] == 0


def test_cli_brief_and_foreign_lease_preflight(workspace, capsys):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"],
             "capabilities": [], "brief_paths": ["src/a.py"]}
    code, added = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 0
    lease = team.claim(workspace, "foreign", ["src/**"], owner="owner")
    code, refused = run(capsys, workspace, "claim", "ONE", "--expect", added["item"]["revision"], "--lane", "writer")
    assert code == 1 and refused["reason"] == "blocked"
    assert refused["blockers"][0]["reason"] == "foreign_lease"
    team.release(workspace, "foreign", lease.oid, caller="owner")
    assert run(capsys, workspace, "claim", "ONE", "--expect", added["item"]["revision"], "--lane", "writer")[0] == 0


@pytest.mark.parametrize("branch", [None, "lane/writer", "refs/heads/lane/writer"])
def test_cli_queue_branch_evidence_is_explicit(workspace, capsys, branch):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    assert run(capsys, workspace, "add", "--item", json.dumps(value))[0] == 0
    revision = team_queue.list(workspace)["items"][0]["revision"]
    args = ["claim", "ONE", "--expect", revision, "--lane", "writer"]
    if branch is not None:
        args.extend(["--branch", branch])
    code, claimed = run(capsys, workspace, *args)
    assert code == 0
    assert claimed["item"]["branch"] == (None if branch is None else "lane/writer")
    team.claim(workspace, "writer", ["src/**"], owner="owner", branch="lane/writer")
    subprocess.run(["git", "symbolic-ref", "HEAD", "refs/heads/other"], cwd=workspace, check=True)
    code, audited = run(capsys, workspace, "audit")
    assert code == 0
    assert [row["code"] for row in audited["findings"]] == (["CLAIM-BRANCH-UNKNOWN"] if branch is None else [])


@pytest.mark.parametrize("branch,accepted", [
    ("feature/c++", True), ("fix/issue#12", True), ("user@topic", True), ("feat/naïve", True),
    ("refs/heads/x", True), ("x" * 200, True), ("x" * 201, False),
    ("refs/tags/x", False), ("HEAD", False), ("private-value topic", False),
    ("private-value\ntrailer", False),
], ids=["plus", "hash", "at", "unicode", "full", "limit", "over-limit", "tag", "head", "space", "multiline"])
def test_cli_queue_uses_lease_branch_grammar(workspace, capsys, branch, accepted):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    code, added = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 0
    if accepted:
        team.claim(workspace, "writer", ["src/**"], owner="owner", branch=branch)
    code, result = run(capsys, workspace, "claim", "ONE", "--expect", added["item"]["revision"],
                       "--lane", "writer", "--branch", branch)
    if accepted:
        assert code == 0, result
        assert result["item"]["branch"] == branch.removeprefix("refs/heads/")
        code, audited = run(capsys, workspace, "audit")
        assert code == 0 and audited["findings"] == []
    else:
        assert code == 2 and result["reason"] == "invalid_arguments"
        assert "private-value" not in json.dumps(result)


@pytest.mark.parametrize("branch,unsupported", [
    ("refs/heads/refs/tags/x", True), ("refs/heads/refs/heads/x", True),
    ("refs/heads/refs/remotes/origin/x", True), ("lane/writer", False),
], ids=["nested-tag", "nested-head", "nested-remote", "valid"])
@pytest.mark.parametrize("state", ["active", "expired", "completed"])
@pytest.mark.parametrize("verb", ["list", "audit", "compact", "add", "claim", "release", "done"])
def test_cli_stored_branch_isolated_from_queue_operations(workspace, capsys, monkeypatch, branch, unsupported, state, verb):
    root = workspace
    monkeypatch.setattr(team_queue, "time", SimpleNamespace(time=lambda: 100))
    (root / ".aegis" / "team.json").write_text(json.dumps({"v": 1,
        "lanes": {"writer": ["src/**"], "beta": ["docs/**"]}}), encoding="utf-8")
    profile = root / ".aegis" / "team" / "profile.json"
    profile.parent.mkdir()
    profile.write_text(json.dumps({"version": 1, "run_config": {"limits": {"writers_max": 2}}}), encoding="utf-8")
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    code, added = run(capsys, root, "add", "--item", json.dumps(value))
    assert code == 0
    code, second = run(capsys, root, "add", "--item", json.dumps({**value, "id": "TWO", "paths": ["docs/**"]}))
    assert code == 0
    code, claimed = run(capsys, root, "claim", "ONE", "--expect", added["item"]["revision"],
                         "--lane", "writer", "--branch", "lane/writer", "--ttl", "10")
    assert code == 0
    if state == "completed":
        assert run(capsys, root, "done", "ONE", "--expect", claimed["item"]["revision"], "--lane", "writer")[0] == 0
    path = root / ".aegis" / "state" / "team-queue.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["items"]["ONE"]["branch"] = branch
    path.write_text(json.dumps(document), encoding="utf-8")
    revision = document["items"]["ONE"]["revision"]
    team.claim(root, "writer", ["src/**"], owner="owner", branch="lane/writer", now=100)
    team.claim(root, "beta", ["docs/**"], owner="owner", branch="lane/beta", now=100)
    moment = 112 if state == "expired" else 103
    monkeypatch.setattr(team_queue, "time", SimpleNamespace(time=lambda: moment))
    arguments = [verb]
    if verb == "list":
        arguments.append("--include-done")
    elif verb == "add":
        arguments.extend(["--item", json.dumps({**value, "id": "THREE", "paths": ["other/**"]})])
    elif verb == "claim":
        arguments.extend(["TWO", "--expect", second["item"]["revision"], "--lane", "beta", "--branch", "lane/beta"])
    elif verb in ("release", "done"):
        arguments.extend(["ONE", "--expect", revision, "--lane", "writer"])
    code, result = run(capsys, root, *arguments)
    expected_error = ("not_claimed" if state == "completed" else "lease_expired"
                      if state == "expired" and verb == "done" else None) if verb in ("release", "done") else None
    if expected_error:
        assert code == 1 and result["reason"] == expected_error
    else:
        assert code == 0, result
    cleared = ((verb == "release" and state != "completed") or
               (verb == "done" and state == "active") or (verb == "compact" and state == "completed"))
    code, audited = run(capsys, root, "audit")
    assert code == 0, audited
    findings = audited["findings"]
    assert [row["code"] for row in findings] == (["CLAIM-BRANCH-UNSUPPORTED"] if unsupported and not cleared else [])
    if findings:
        assert findings[0]["item_id"] == "ONE" and findings[0]["reason"] == "claim_branch_unsupported"
        assert findings[0]["next_action"] and branch not in json.dumps(findings)
    if not cleared:
        assert json.loads(path.read_text(encoding="utf-8"))["items"]["ONE"]["branch"] == branch
    if unsupported and not cleared:
        recovery_args = ["compact"] if state == "completed" else ["release", "ONE", "--expect", revision, "--lane", "writer"]
        assert run(capsys, root, *recovery_args)[0] == 0
        assert run(capsys, root, "audit")[1]["findings"] == []


@pytest.mark.parametrize("lease_state,lease_code", [
    ("missing", "LANE-NO-LEASE"), ("branchless", "LEASE-BRANCH-UNKNOWN"),
    ("unreadable", "LEASE-UNREADABLE"), ("healthy", None),
])
def test_cli_unsupported_branch_preserves_independent_lease_findings(workspace, capsys, monkeypatch, lease_state, lease_code):
    from aegis_core import gitsafe

    root = workspace
    monkeypatch.setattr(team_queue, "time", SimpleNamespace(time=lambda: 100))
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    code, added = run(capsys, root, "add", "--item", json.dumps(value))
    assert code == 0
    code, claimed = run(capsys, root, "claim", "ONE", "--expect", added["item"]["revision"],
                        "--lane", "writer", "--branch", "lane/writer")
    assert code == 0
    branch = "refs/heads/refs/tags/private-value"
    path = root / ".aegis" / "state" / "team-queue.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["items"]["ONE"]["branch"] = branch
    path.write_text(json.dumps(document), encoding="utf-8")
    if lease_state == "unreadable":
        bad = gitsafe.write_blob(root, b"{}")
        gitsafe.update_ref(root, team.lane_ref("writer"), bad, None)
    elif lease_state != "missing":
        team.claim(root, "writer", ["src/**"], owner="owner", now=100,
                   branch=None if lease_state == "branchless" else "other/branch")
    code, result = run(capsys, root, "audit")
    assert code == 0, result
    findings = result["findings"]
    expected = ["CLAIM-BRANCH-UNSUPPORTED"] + ([lease_code] if lease_code else [])
    assert [row["code"] for row in findings] == expected
    assert all(row["item_id"] == "ONE" and row["lane"] == "writer" and
               row["refused"] and row["reason"] and row["next_action"] for row in findings)
    assert "private-value" not in json.dumps(findings)
    assert json.loads(path.read_text(encoding="utf-8"))["items"]["ONE"]["branch"] == branch


def test_cli_outside_brief_is_refused_at_add_and_corrected_retry_succeeds(workspace, capsys):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": [], "brief_paths": ["docs/a.md"]}
    code, result = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 2 and result["reason"] == "brief_outside_scope"
    assert not (workspace / ".aegis" / "state" / "team-queue.json").exists()
    value["brief_paths"] = ["src/a.py"]
    assert run(capsys, workspace, "add", "--item", json.dumps(value))[0] == 0


def test_queue_with_model_data_keeps_workspace_refusal(tmp_path, capsys):
    code, result = run(capsys, tmp_path, "list", "--capability", "model",
                       "--workspace", "token=private-value/missing")
    assert code == 1 and result["reason"] == "queue_io_unavailable"
    assert "private-value" not in json.dumps(result)


@pytest.mark.parametrize("position", [0, 1], ids=["root", "team"])
def test_queue_model_data_works_with_ancestor_option_abbreviation(workspace, capsys, position):
    argv = ["team", "queue", "list", "--capability", "model"]
    argv[position:position] = ["--js", "--workspace", str(workspace)]
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out)["schema"] == "aegis.team.queue.list/v1"


def test_model_values_are_queue_identifiers(workspace, capsys):
    (workspace / ".aegis" / "team.json").write_text(
        json.dumps({"v": 1, "lanes": {"model": ["src/**"]}}), encoding="utf-8")
    value = {"id": "model", "title": "Work", "paths": ["src/**"], "capabilities": ["model"]}
    code, added = run(capsys, workspace, "add", "--item", json.dumps(value))
    assert code == 0
    code, claimed = run(capsys, workspace, "claim", "model", "--expect", added["item"]["revision"],
                        "--lane", "model", "--capability", "model")
    assert code == 0, claimed
    assert run(capsys, workspace, "list", "--capability", "model")[1]["items"][0]["id"] == "model"
    code, released = run(capsys, workspace, "release", "model", "--expect", claimed["item"]["revision"], "--lane", "model")
    assert code == 0
    code, claimed = run(capsys, workspace, "claim", "model", "--expect", released["item"]["revision"],
                        "--lane", "model", "--capability", "model")
    assert code == 0
    assert run(capsys, workspace, "done", "model", "--expect", claimed["item"]["revision"], "--lane", "model")[0] == 0

@pytest.mark.parametrize("mode", ["json", "text"])
def test_legacy_refusal_changes_only_by_optional_hint(workspace, capsys, monkeypatch, mode):
    monkeypatch.setattr(cli_team, "time", SimpleNamespace(time=lambda: 1760000000))
    hint = "Retry with root-anchored lease paths: /pyproject.toml; slashless paths cover every depth."
    current = [""]
    def refused(*args, **kwargs):
        raise team.LeaseRefused("overlap: fixed refusal", "overlap", "writer",
                                lanes=("docs",), next_action=current[0])
    monkeypatch.setattr(cli_team, "team", SimpleNamespace(**{**vars(team), "claim": refused}))
    args = ["--workspace", str(workspace), "team", "claim", "writer", "--paths", "pyproject.toml"]
    if mode == "json":
        args.append("--json")
    assert main(args) == 1
    baseline = capsys.readouterr()
    current[0] = hint
    assert main(args) == 1
    changed = capsys.readouterr()
    if mode == "json":
        assert "next_action" not in json.loads(baseline.out)
        assert changed.out.replace(',\n  "next_action": ' + json.dumps(hint), "") == baseline.out
        assert baseline.err == changed.err == ""
    else:
        assert baseline.out == changed.out == ""
        assert changed.err.replace(hint + "\n", "") == baseline.err


# Operational compatibility rows are captured from review_base e983c16226dd
# under the original
# module names. Digests cover [exit, complete stdout, complete stderr]; full raw
# captures and source identities accompany the handoff.
OPERATION_GOLDENS = {'cli-queue/unclaim/writer_live/text': '34e3221632188bc94d258fdd8ceedd40ebe5d67e0c7d91f3eaed4709ec81a20e',
 'cli-queue/unclaim/writer_live/json': '34e3221632188bc94d258fdd8ceedd40ebe5d67e0c7d91f3eaed4709ec81a20e',
 'core-queue/unclaim/writer_live/dict': '34e3221632188bc94d258fdd8ceedd40ebe5d67e0c7d91f3eaed4709ec81a20e',
 'cli-queue/add/valid/text': 'fe60c6c01c8f5adeaa653e6bf7a8fc21258ce0c4da7c1faeec909b181a56e5ff',
 'cli-queue/add/valid/json': 'fe60c6c01c8f5adeaa653e6bf7a8fc21258ce0c4da7c1faeec909b181a56e5ff',
 'cli-queue/add/oversized/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/add/oversized/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/add/invalid_arguments/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/add/invalid_arguments/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/add/invalid_queue_state/text': '36bdeb232103e9f988b24e8647c78c018824c8119e8dac18a1eb0a17c078a55f',
 'cli-queue/add/invalid_queue_state/json': '36bdeb232103e9f988b24e8647c78c018824c8119e8dac18a1eb0a17c078a55f',
 'cli-queue/add/queue_size_limit/text': '422b1424cbf27a5da29c09f5480682bab8a32c8b489f8e005720469b327bd0b3',
 'cli-queue/add/queue_size_limit/json': '422b1424cbf27a5da29c09f5480682bab8a32c8b489f8e005720469b327bd0b3',
 'cli-queue/add/unsupported_platform/text': '9046b2c94b44085f9dd65236e0015aefaeeca254e4e5683d2277166ec8c8a76d',
 'cli-queue/add/unsupported_platform/json': '9046b2c94b44085f9dd65236e0015aefaeeca254e4e5683d2277166ec8c8a76d',
 'cli-queue/add/queue_io_unavailable/text': '076be5182905950e062bf745ec3d9c9d24717b027c6ec8b2ed07b0e09b160767',
 'cli-queue/add/queue_io_unavailable/json': '076be5182905950e062bf745ec3d9c9d24717b027c6ec8b2ed07b0e09b160767',
 'cli-queue/add/unclaim_recovery_required/text': 'fb9e6b25c1cf24c437e58259cc22c938d37b351b0ba8cc288e080b79807c29b6',
 'cli-queue/add/unclaim_recovery_required/json': 'fb9e6b25c1cf24c437e58259cc22c938d37b351b0ba8cc288e080b79807c29b6',
 'cli-queue/add/queue_lock_timeout/text': '1176100526574bbe097182b0b3fdc31cc5748a8db5545c6bcb596eee786e7f84',
 'cli-queue/add/queue_lock_timeout/json': '1176100526574bbe097182b0b3fdc31cc5748a8db5545c6bcb596eee786e7f84',
 'cli-queue/add/invalid_item/text': '0986a7112917571703c5c62cfa10aceeb8b64e42ec2687c5211706f0f7d9091a',
 'cli-queue/add/invalid_item/json': '0986a7112917571703c5c62cfa10aceeb8b64e42ec2687c5211706f0f7d9091a',
 'cli-queue/add/credential_like_text/text': '5036199db92e4d88cc81b2d1b438eefcb1c593dede21ce2775b25b41b6cfb6b3',
 'cli-queue/add/credential_like_text/json': '5036199db92e4d88cc81b2d1b438eefcb1c593dede21ce2775b25b41b6cfb6b3',
 'cli-queue/add/brief_outside_scope/text': '7f418de9099878e276dabfaede2c64ccc189e6b2d9c3d0e0e6fcf96fba421e31',
 'cli-queue/add/brief_outside_scope/json': '7f418de9099878e276dabfaede2c64ccc189e6b2d9c3d0e0e6fcf96fba421e31',
 'cli-queue/add/item_exists/text': 'd2522f7ca2d46e5fa8dee2fa86b068130d317d5f86832ec43eb49d36d17d2ce5',
 'cli-queue/add/item_exists/json': 'd2522f7ca2d46e5fa8dee2fa86b068130d317d5f86832ec43eb49d36d17d2ce5',
 'cli-queue/add/queue_live_limit/text': '22f5e94f8ba4963bd2045c3a6e4b2e48c902267bbee116902b0ecc57ebe247c1',
 'cli-queue/add/queue_live_limit/json': '22f5e94f8ba4963bd2045c3a6e4b2e48c902267bbee116902b0ecc57ebe247c1',
 'cli-queue/list/valid/text': 'e2aa77edee7605b2f5f54574234c15e21e2a0eb6d65523fe65f323751726eb5e',
 'cli-queue/list/valid/json': 'e2aa77edee7605b2f5f54574234c15e21e2a0eb6d65523fe65f323751726eb5e',
 'cli-queue/list/oversized/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/list/oversized/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/list/invalid_arguments/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/list/invalid_arguments/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/list/invalid_queue_state/text': '937a3e6369c5979848a9b33b136117a285b0da9c535d4acf6c8000ba37c16159',
 'cli-queue/list/invalid_queue_state/json': '937a3e6369c5979848a9b33b136117a285b0da9c535d4acf6c8000ba37c16159',
 'cli-queue/list/queue_size_limit/text': '1cb9ecbdbe5436122633800ec39e79fc59e72cdc1fefb190093ebe10e6dc279b',
 'cli-queue/list/queue_size_limit/json': '1cb9ecbdbe5436122633800ec39e79fc59e72cdc1fefb190093ebe10e6dc279b',
 'cli-queue/list/unsupported_platform/text': '28c8057c096ff42602b497058bc754987f7accd6da49937c3908f057e3d62b74',
 'cli-queue/list/unsupported_platform/json': '28c8057c096ff42602b497058bc754987f7accd6da49937c3908f057e3d62b74',
 'cli-queue/list/queue_io_unavailable/text': '4b305060eb0acb7ee5f98f87d2e7470f05191f720c2fe51ef1c1fa0e41deb31e',
 'cli-queue/list/queue_io_unavailable/json': '4b305060eb0acb7ee5f98f87d2e7470f05191f720c2fe51ef1c1fa0e41deb31e',
 'cli-queue/list/unclaim_recovery_required/text': 'e9b3f8ea00e0ce97f06f7cc7dc171d6f8ff0a79482182a9809fb2f768b577c5a',
 'cli-queue/list/unclaim_recovery_required/json': 'e9b3f8ea00e0ce97f06f7cc7dc171d6f8ff0a79482182a9809fb2f768b577c5a',
 'cli-queue/list/malformed_capability/text': '53f5598604c932505815550cd9c4affb30c6c0c2913dc7e6ccf05fb0de26d6cc',
 'cli-queue/list/malformed_capability/json': '53f5598604c932505815550cd9c4affb30c6c0c2913dc7e6ccf05fb0de26d6cc',
 'cli-queue/claim/valid/text': '61fb2b965c21d5253358ad827146f8fa098e96107383b79a6a57a93f701580f9',
 'cli-queue/claim/valid/json': '61fb2b965c21d5253358ad827146f8fa098e96107383b79a6a57a93f701580f9',
 'cli-queue/claim/oversized/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/claim/oversized/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/claim/invalid_arguments/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/claim/invalid_arguments/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/claim/invalid_queue_state/text': '811097086c4cb3960c20a62e96fa920ae631ccaf80eab88bc1496aa7a0483030',
 'cli-queue/claim/invalid_queue_state/json': '811097086c4cb3960c20a62e96fa920ae631ccaf80eab88bc1496aa7a0483030',
 'cli-queue/claim/queue_size_limit/text': 'a7feb4499d39dc0fae5b217db4d463f0adb1c489a175a846dd28ad623f1c6159',
 'cli-queue/claim/queue_size_limit/json': 'a7feb4499d39dc0fae5b217db4d463f0adb1c489a175a846dd28ad623f1c6159',
 'cli-queue/claim/unsupported_platform/text': '66bf00fd466720cc01526a66deed38bd2bb8d7b1301aa3e7fe7ed14b501a548d',
 'cli-queue/claim/unsupported_platform/json': '66bf00fd466720cc01526a66deed38bd2bb8d7b1301aa3e7fe7ed14b501a548d',
 'cli-queue/claim/queue_io_unavailable/text': 'cd0f825a901ff47b4c6eefadf62c9f105fc7e0902a28a7a72d015474033cd2aa',
 'cli-queue/claim/queue_io_unavailable/json': 'cd0f825a901ff47b4c6eefadf62c9f105fc7e0902a28a7a72d015474033cd2aa',
 'cli-queue/claim/unclaim_recovery_required/text': 'a23905a0c892722c7f80d6c9989e910f8d8199544c5fc68c102b08c2e070b344',
 'cli-queue/claim/unclaim_recovery_required/json': 'a23905a0c892722c7f80d6c9989e910f8d8199544c5fc68c102b08c2e070b344',
 'cli-queue/claim/queue_lock_timeout/text': '7739bdc289ed6886be4312eb5203ecc618159b385db2564aadd1cb03c929d4eb',
 'cli-queue/claim/queue_lock_timeout/json': '7739bdc289ed6886be4312eb5203ecc618159b385db2564aadd1cb03c929d4eb',
 'cli-queue/claim/item_missing/text': '85cf7a4a7babacd5224dc12334cbb6302f60f6bc33d3a3667f4cc74b1f58656d',
 'cli-queue/claim/item_missing/json': '85cf7a4a7babacd5224dc12334cbb6302f60f6bc33d3a3667f4cc74b1f58656d',
 'cli-queue/claim/stale_revision/text': 'd14544c058b8556442703607c63beda479c1dbb4b959c0bec38ff1a1d52b78cc',
 'cli-queue/claim/stale_revision/json': 'd14544c058b8556442703607c63beda479c1dbb4b959c0bec38ff1a1d52b78cc',
 'cli-queue/claim/already_claimed/text': '2b729b4890fefc7a599e4b15c7bc24e310b90cdd2f7623e9477d2fd67b15efb5',
 'cli-queue/claim/already_claimed/json': '2b729b4890fefc7a599e4b15c7bc24e310b90cdd2f7623e9477d2fd67b15efb5',
 'cli-queue/claim/lane_busy/text': '499ec0798577cae32f1b9e8e46e3373d6aa54c790616c007e81a3c495e75bf77',
 'cli-queue/claim/lane_busy/json': '499ec0798577cae32f1b9e8e46e3373d6aa54c790616c007e81a3c495e75bf77',
 'cli-queue/claim/capability_mismatch/text': '1423c5554cc2c4a156a64facd10ab8e230f968fa7b8070834bffb80f2be422a5',
 'cli-queue/claim/capability_mismatch/json': '1423c5554cc2c4a156a64facd10ab8e230f968fa7b8070834bffb80f2be422a5',
 'cli-queue/claim/blocked/text': '6bfe925d5d77c4c441e8e14dc22bb378bb3b1d803555637767b399479875c522',
 'cli-queue/claim/blocked/json': '6bfe925d5d77c4c441e8e14dc22bb378bb3b1d803555637767b399479875c522',
 'cli-queue/claim/profile_unavailable/text': 'f3be0382a02825f69514c9f0bd12fa9a1659e4d79f7c43ac8a5115dbf0f47f1a',
 'cli-queue/claim/profile_unavailable/json': 'f3be0382a02825f69514c9f0bd12fa9a1659e4d79f7c43ac8a5115dbf0f47f1a',
 'cli-queue/claim/capacity_full/text': 'f2624cccec766f0096839c390a31f9caf1aa6a6c64bc458c1131f01241a94d58',
 'cli-queue/claim/capacity_full/json': 'f2624cccec766f0096839c390a31f9caf1aa6a6c64bc458c1131f01241a94d58',
 'cli-queue/claim/item_done/text': 'c483155ed60f67b9d2bcbea8305aa61712672f8814deb3868536c8292e8c9812',
 'cli-queue/claim/item_done/json': 'c483155ed60f67b9d2bcbea8305aa61712672f8814deb3868536c8292e8c9812',
 'cli-queue/claim/malformed_identifier/text': 'f0ce39215e2d0a7bea16ea2c3b435ed98752a3252eee696e5b176bca2876ccd7',
 'cli-queue/claim/malformed_identifier/json': 'f0ce39215e2d0a7bea16ea2c3b435ed98752a3252eee696e5b176bca2876ccd7',
 'cli-queue/claim/malformed_revision/text': 'f0ce39215e2d0a7bea16ea2c3b435ed98752a3252eee696e5b176bca2876ccd7',
 'cli-queue/claim/malformed_revision/json': 'f0ce39215e2d0a7bea16ea2c3b435ed98752a3252eee696e5b176bca2876ccd7',
 'cli-queue/release/valid/text': 'a332c486d97e886e7c2318c7ab19583d42db77078c82ff2fee81c55a773b7a0b',
 'cli-queue/release/valid/json': 'a332c486d97e886e7c2318c7ab19583d42db77078c82ff2fee81c55a773b7a0b',
 'cli-queue/release/oversized/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/release/oversized/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/release/invalid_arguments/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/release/invalid_arguments/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/release/invalid_queue_state/text': 'ac56c1f08d0a1177751b88830d5fb35440433872805f7a91643012c276479636',
 'cli-queue/release/invalid_queue_state/json': 'ac56c1f08d0a1177751b88830d5fb35440433872805f7a91643012c276479636',
 'cli-queue/release/queue_size_limit/text': 'a5c0dad600c7cc498ae3e40b82e987454f67eefe687fddc2361ac93f979f132c',
 'cli-queue/release/queue_size_limit/json': 'a5c0dad600c7cc498ae3e40b82e987454f67eefe687fddc2361ac93f979f132c',
 'cli-queue/release/unsupported_platform/text': '6538f2912f2a97e0c51f5cd9af5756995096937c6387c28d0ff7de441291f405',
 'cli-queue/release/unsupported_platform/json': '6538f2912f2a97e0c51f5cd9af5756995096937c6387c28d0ff7de441291f405',
 'cli-queue/release/queue_io_unavailable/text': '601d21284be47d94ddcb2f90b9e1338da2fa162bc9ac927f95b4e9741e256ea2',
 'cli-queue/release/queue_io_unavailable/json': '601d21284be47d94ddcb2f90b9e1338da2fa162bc9ac927f95b4e9741e256ea2',
 'cli-queue/release/unclaim_recovery_required/text': '265a5d1740bc8044625f06e33ee7a718ac18fefa922742d80fa1c1425c95e717',
 'cli-queue/release/unclaim_recovery_required/json': '265a5d1740bc8044625f06e33ee7a718ac18fefa922742d80fa1c1425c95e717',
 'cli-queue/release/queue_lock_timeout/text': 'cf698dfdd97abbfeedcf9a867995273ccac64e2eb59f655871cd05d1aba9b26e',
 'cli-queue/release/queue_lock_timeout/json': 'cf698dfdd97abbfeedcf9a867995273ccac64e2eb59f655871cd05d1aba9b26e',
 'cli-queue/release/item_missing/text': 'bfba77d4480e22d080aec23200025ea0bc53bec2665c77927400a70953c15cd9',
 'cli-queue/release/item_missing/json': 'bfba77d4480e22d080aec23200025ea0bc53bec2665c77927400a70953c15cd9',
 'cli-queue/release/stale_revision/text': '3039ef59fd14380142132480af7d41b99e25022f6bcfba2feac53ac911ae5c7f',
 'cli-queue/release/stale_revision/json': '3039ef59fd14380142132480af7d41b99e25022f6bcfba2feac53ac911ae5c7f',
 'cli-queue/release/not_claimed/text': 'f885827072cb86a2a8e21cd450b644cc3722e8617890c1b16aa26181622a36f3',
 'cli-queue/release/not_claimed/json': 'f885827072cb86a2a8e21cd450b644cc3722e8617890c1b16aa26181622a36f3',
 'cli-queue/release/lane_required/text': '5ca45d0667901561fb9239e3d3e6b97aac93e0109c04a805fddf7662318049cf',
 'cli-queue/release/lane_required/json': '5ca45d0667901561fb9239e3d3e6b97aac93e0109c04a805fddf7662318049cf',
 'cli-queue/release/lane_mismatch/text': 'ac6b750f6439aca59d642aea4fb4aa9b85d19905e84abdbf854644e52d4bda43',
 'cli-queue/release/lane_mismatch/json': 'ac6b750f6439aca59d642aea4fb4aa9b85d19905e84abdbf854644e52d4bda43',
 'cli-queue/release/item_done/text': '15a169496d59bdead2a22d8e16dc938f879a64d649e6de18154ca3aacbe50aa0',
 'cli-queue/release/item_done/json': '15a169496d59bdead2a22d8e16dc938f879a64d649e6de18154ca3aacbe50aa0',
 'cli-queue/release/malformed_identifier/text': '783f942711092278a3cbfc766a33f9729a2b4df21686125f4006e2c4f7794bc8',
 'cli-queue/release/malformed_identifier/json': '783f942711092278a3cbfc766a33f9729a2b4df21686125f4006e2c4f7794bc8',
 'cli-queue/release/malformed_revision/text': '783f942711092278a3cbfc766a33f9729a2b4df21686125f4006e2c4f7794bc8',
 'cli-queue/release/malformed_revision/json': '783f942711092278a3cbfc766a33f9729a2b4df21686125f4006e2c4f7794bc8',
 'cli-queue/unclaim/valid/text': 'd625e2e8a2231321c8df1dbe3d98d62a2f469b9c959b28dcd7e0c8a1ce27e981',
 'cli-queue/unclaim/valid/json': 'd625e2e8a2231321c8df1dbe3d98d62a2f469b9c959b28dcd7e0c8a1ce27e981',
 'cli-queue/unclaim/oversized/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/unclaim/oversized/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/unclaim/invalid_arguments/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/unclaim/invalid_arguments/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/unclaim/invalid_queue_state/text': 'dbd06f15947bc203cf16824787f342d875f619e7edab38ded52203fa313bb6f5',
 'cli-queue/unclaim/invalid_queue_state/json': 'dbd06f15947bc203cf16824787f342d875f619e7edab38ded52203fa313bb6f5',
 'cli-queue/unclaim/queue_size_limit/text': '0e84e1320da05f0ea3bc26c2427f4d2fb4bb5d8205d8e16057e7db95442eab98',
 'cli-queue/unclaim/queue_size_limit/json': '0e84e1320da05f0ea3bc26c2427f4d2fb4bb5d8205d8e16057e7db95442eab98',
 'cli-queue/unclaim/unsupported_platform/text': '167ea7453eb1b2208e17da2655d0d47349f0dc89bed3f65a49462e055de4cdfb',
 'cli-queue/unclaim/unsupported_platform/json': '167ea7453eb1b2208e17da2655d0d47349f0dc89bed3f65a49462e055de4cdfb',
 'cli-queue/unclaim/queue_io_unavailable/text': 'f0475ed9e2ab8d95388a5adbe4f7937fd1ad383264c7fc984645e444186a4797',
 'cli-queue/unclaim/queue_io_unavailable/json': 'f0475ed9e2ab8d95388a5adbe4f7937fd1ad383264c7fc984645e444186a4797',
 'cli-queue/unclaim/unclaim_recovery_required/text': '0b5f3900beda42379bf4c3f533d7831fa1e10d6e8cc8a76087a223dbfd183935',
 'cli-queue/unclaim/unclaim_recovery_required/json': '0b5f3900beda42379bf4c3f533d7831fa1e10d6e8cc8a76087a223dbfd183935',
 'cli-queue/unclaim/queue_lock_timeout/text': 'd21cc1117bcbc9141d081ae2acc629889bc12deeddbf91802a99248dc1271d07',
 'cli-queue/unclaim/queue_lock_timeout/json': 'd21cc1117bcbc9141d081ae2acc629889bc12deeddbf91802a99248dc1271d07',
 'cli-queue/unclaim/item_missing/text': '2049cf09e3756e1ade4b6a7fd4a1dafa0d921ae9449627205d59a0e58f78b714',
 'cli-queue/unclaim/item_missing/json': '2049cf09e3756e1ade4b6a7fd4a1dafa0d921ae9449627205d59a0e58f78b714',
 'cli-queue/unclaim/stale_revision/text': '317b984d6ba9db6fad5a83ea7ab83116874fbaa8d1741bfb86e2a4e02d4fe0c7',
 'cli-queue/unclaim/stale_revision/json': '317b984d6ba9db6fad5a83ea7ab83116874fbaa8d1741bfb86e2a4e02d4fe0c7',
 'cli-queue/unclaim/not_claimed/text': 'ce081c1565218fed8abbad661f50b91fc014eb5a4f15c97d9c61c25d451784f1',
 'cli-queue/unclaim/not_claimed/json': 'ce081c1565218fed8abbad661f50b91fc014eb5a4f15c97d9c61c25d451784f1',
 'cli-queue/unclaim/lane_mismatch/text': '682fb4c94b7ca61254df331cc8412d6b129ec54781e3b3cd15af02ed29a2fa44',
 'cli-queue/unclaim/lane_mismatch/json': '682fb4c94b7ca61254df331cc8412d6b129ec54781e3b3cd15af02ed29a2fa44',
 'cli-queue/unclaim/writer_not_stopped/text': '8df21067e1acf192e8552d2394a91169d6bfd02ca51fc78202fa25b6e9ae1a40',
 'cli-queue/unclaim/writer_not_stopped/json': '8df21067e1acf192e8552d2394a91169d6bfd02ca51fc78202fa25b6e9ae1a40',
 'cli-queue/unclaim/invalid_item/text': '7682b940c50da9ed952866522aa9beb1756dcfd06d4596bf48144f23e273453b',
 'cli-queue/unclaim/invalid_item/json': '7682b940c50da9ed952866522aa9beb1756dcfd06d4596bf48144f23e273453b',
 'cli-queue/unclaim/credential_like_text/text': 'fd5ce42284f23d2176dc5feb625d98dd5067e60bf73b19eb1d321097a13435d8',
 'cli-queue/unclaim/credential_like_text/json': 'fd5ce42284f23d2176dc5feb625d98dd5067e60bf73b19eb1d321097a13435d8',
 'cli-queue/unclaim/unclaim_lease_refused/text': '7f78fbde2ffe6f4ccb2359eb7178c62dd9d6242ba463d37927a869d875eac1ce',
 'cli-queue/unclaim/unclaim_lease_refused/json': '7f78fbde2ffe6f4ccb2359eb7178c62dd9d6242ba463d37927a869d875eac1ce',
 'cli-queue/unclaim/unclaim_event_unavailable/text': 'a694e6bdbd419f944a80d323aee31f12a52f3bb265c07f60fb0d93086d6db0cd',
 'cli-queue/unclaim/unclaim_event_unavailable/json': 'a694e6bdbd419f944a80d323aee31f12a52f3bb265c07f60fb0d93086d6db0cd',
 'cli-queue/unclaim/item_done/text': 'e7be3b9f08663fac2f74e2294178117ecc53712cffa51e1d690f80a7899f6260',
 'cli-queue/unclaim/item_done/json': 'e7be3b9f08663fac2f74e2294178117ecc53712cffa51e1d690f80a7899f6260',
 'cli-queue/unclaim/malformed_identifier/text': 'a1d1e6bbf34e1f0a11d037ce28ef359b528569dcda040d25941dcc7d2d2ee24a',
 'cli-queue/unclaim/malformed_identifier/json': 'a1d1e6bbf34e1f0a11d037ce28ef359b528569dcda040d25941dcc7d2d2ee24a',
 'cli-queue/unclaim/malformed_revision/text': 'a1d1e6bbf34e1f0a11d037ce28ef359b528569dcda040d25941dcc7d2d2ee24a',
 'cli-queue/unclaim/malformed_revision/json': 'a1d1e6bbf34e1f0a11d037ce28ef359b528569dcda040d25941dcc7d2d2ee24a',
 'cli-queue/done/valid/text': 'a48a642c7f115e374f3d5b2ee97a960dd44b24b3d20c0c011e1a8aafda7c1b41',
 'cli-queue/done/valid/json': 'a48a642c7f115e374f3d5b2ee97a960dd44b24b3d20c0c011e1a8aafda7c1b41',
 'cli-queue/done/oversized/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/done/oversized/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/done/invalid_arguments/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/done/invalid_arguments/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/done/invalid_queue_state/text': '1e4263b92b87c79508269f6f3cc275ec16f61f29edeecb222a4149a01ce435a9',
 'cli-queue/done/invalid_queue_state/json': '1e4263b92b87c79508269f6f3cc275ec16f61f29edeecb222a4149a01ce435a9',
 'cli-queue/done/queue_size_limit/text': '5275a13308b631cfe193b731dbb7537c2bf6da450ba58fb5019803d32ee00d02',
 'cli-queue/done/queue_size_limit/json': '5275a13308b631cfe193b731dbb7537c2bf6da450ba58fb5019803d32ee00d02',
 'cli-queue/done/unsupported_platform/text': '793368da2e2be43759a652f2850f579a4385e64988b85551f7fd2f952c3f32c0',
 'cli-queue/done/unsupported_platform/json': '793368da2e2be43759a652f2850f579a4385e64988b85551f7fd2f952c3f32c0',
 'cli-queue/done/queue_io_unavailable/text': '15cda7ef56b8fe55f7306a9855a8a9a2733ad13fae7f59005d70630949122f78',
 'cli-queue/done/queue_io_unavailable/json': '15cda7ef56b8fe55f7306a9855a8a9a2733ad13fae7f59005d70630949122f78',
 'cli-queue/done/unclaim_recovery_required/text': '40c7902fe7fec1f2a6f77cb40b21fcf5442e2365e6f0447e72a84a5eafad714f',
 'cli-queue/done/unclaim_recovery_required/json': '40c7902fe7fec1f2a6f77cb40b21fcf5442e2365e6f0447e72a84a5eafad714f',
 'cli-queue/done/queue_lock_timeout/text': '50bae5e5bff01926ed9872f688738744c84c9ba3b29a64fa7ca3fc9ad12db272',
 'cli-queue/done/queue_lock_timeout/json': '50bae5e5bff01926ed9872f688738744c84c9ba3b29a64fa7ca3fc9ad12db272',
 'cli-queue/done/item_missing/text': 'a6d1151bbf5952078f361eb73135d8011a180226c589482908f125bed1e61d5f',
 'cli-queue/done/item_missing/json': 'a6d1151bbf5952078f361eb73135d8011a180226c589482908f125bed1e61d5f',
 'cli-queue/done/stale_revision/text': '7b2c390a4a4aad036400ad6ed53703aea29da8fc0a64859fbe036f70960ada44',
 'cli-queue/done/stale_revision/json': '7b2c390a4a4aad036400ad6ed53703aea29da8fc0a64859fbe036f70960ada44',
 'cli-queue/done/not_claimed/text': 'a8e231e1c6441b089b10af8e8cab720b7fcce49bd6b0d77a4b2be3051a7ae102',
 'cli-queue/done/not_claimed/json': 'a8e231e1c6441b089b10af8e8cab720b7fcce49bd6b0d77a4b2be3051a7ae102',
 'cli-queue/done/lane_required/text': '4051be226741d072601e5ed3f0163b6df7a08667e6335424ed86373c3fbe7879',
 'cli-queue/done/lane_required/json': '4051be226741d072601e5ed3f0163b6df7a08667e6335424ed86373c3fbe7879',
 'cli-queue/done/lane_mismatch/text': '3699eebee4da4266f4d1a7425b715625bc9181cbcd0af523e4e6bdd74a769949',
 'cli-queue/done/lane_mismatch/json': '3699eebee4da4266f4d1a7425b715625bc9181cbcd0af523e4e6bdd74a769949',
 'cli-queue/done/lease_expired/text': 'e9fcae4592f2c57c9e4b2342aa0ad6ffb96e6ba01943ad9a9267291689d026e2',
 'cli-queue/done/lease_expired/json': 'e9fcae4592f2c57c9e4b2342aa0ad6ffb96e6ba01943ad9a9267291689d026e2',
 'cli-queue/done/item_done/text': 'dae2b128a274edb60f22ff3748d9050f5f32e146c4e4a9d5b26cbb82dc8e5eb4',
 'cli-queue/done/item_done/json': 'dae2b128a274edb60f22ff3748d9050f5f32e146c4e4a9d5b26cbb82dc8e5eb4',
 'cli-queue/done/malformed_identifier/text': '559465e048e06153d5303a4708f3d52ede5ea7bf6d5474267e77ab2f34a00f6a',
 'cli-queue/done/malformed_identifier/json': '559465e048e06153d5303a4708f3d52ede5ea7bf6d5474267e77ab2f34a00f6a',
 'cli-queue/done/malformed_revision/text': '559465e048e06153d5303a4708f3d52ede5ea7bf6d5474267e77ab2f34a00f6a',
 'cli-queue/done/malformed_revision/json': '559465e048e06153d5303a4708f3d52ede5ea7bf6d5474267e77ab2f34a00f6a',
 'cli-queue/audit/valid/text': 'dd7cb3de450ac174558cc83d108a7026e345cb07753dc034482d2b7f9e583399',
 'cli-queue/audit/valid/json': 'dd7cb3de450ac174558cc83d108a7026e345cb07753dc034482d2b7f9e583399',
 'cli-queue/audit/oversized/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/audit/oversized/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/audit/invalid_arguments/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/audit/invalid_arguments/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/audit/invalid_queue_state/text': '87c019baa6257d1f22c780858fe68fd59e4fc963aae55bb8759b9d06e64329b8',
 'cli-queue/audit/invalid_queue_state/json': '87c019baa6257d1f22c780858fe68fd59e4fc963aae55bb8759b9d06e64329b8',
 'cli-queue/audit/queue_size_limit/text': 'ba2f529bb06ad63ba2c893bf3c8f8331807b0c802f348578c651cf53959a1bf0',
 'cli-queue/audit/queue_size_limit/json': 'ba2f529bb06ad63ba2c893bf3c8f8331807b0c802f348578c651cf53959a1bf0',
 'cli-queue/audit/unsupported_platform/text': '7ddf6bae902ced5c30451c5bcd9c62beb80c74e0d7c2e71918268ccdef27fb3d',
 'cli-queue/audit/unsupported_platform/json': '7ddf6bae902ced5c30451c5bcd9c62beb80c74e0d7c2e71918268ccdef27fb3d',
 'cli-queue/audit/queue_io_unavailable/text': '1009cc95cc9349829123a6f1ed3de48ef77d139a2801a81b4911f8bd0b00b958',
 'cli-queue/audit/queue_io_unavailable/json': '1009cc95cc9349829123a6f1ed3de48ef77d139a2801a81b4911f8bd0b00b958',
 'cli-queue/audit/unclaim_recovery_required/text': '5a52f16452564837baaa7b390dcfe9bde932acca55211d1525d298b35de7b2f7',
 'cli-queue/audit/unclaim_recovery_required/json': '5a52f16452564837baaa7b390dcfe9bde932acca55211d1525d298b35de7b2f7',
 'cli-queue/compact/valid/text': 'd9d28429080e7e43bd5d4645d1bb79787392742f1a827e83529e3d77346277ef',
 'cli-queue/compact/valid/json': 'd9d28429080e7e43bd5d4645d1bb79787392742f1a827e83529e3d77346277ef',
 'cli-queue/compact/oversized/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/compact/oversized/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/compact/invalid_arguments/text': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/compact/invalid_arguments/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'cli-queue/compact/invalid_queue_state/text': 'b7284de87d601465274d65de89db6acd5bec4a314245564496993f1f1be6f043',
 'cli-queue/compact/invalid_queue_state/json': 'b7284de87d601465274d65de89db6acd5bec4a314245564496993f1f1be6f043',
 'cli-queue/compact/queue_size_limit/text': '69c8245416c7f690ab6ac5fc8e60fa0eef3de0a73593be63fb198182094ceb18',
 'cli-queue/compact/queue_size_limit/json': '69c8245416c7f690ab6ac5fc8e60fa0eef3de0a73593be63fb198182094ceb18',
 'cli-queue/compact/unsupported_platform/text': 'fdc3d060fb3cd5e8e392b892aab62ee61f1bffb0ccbbff8f42ce1e387ea8b636',
 'cli-queue/compact/unsupported_platform/json': 'fdc3d060fb3cd5e8e392b892aab62ee61f1bffb0ccbbff8f42ce1e387ea8b636',
 'cli-queue/compact/queue_io_unavailable/text': '6b4c6c6a7293af88d3d74576e5c839e7b77f129631379b34821484022fc99553',
 'cli-queue/compact/queue_io_unavailable/json': '6b4c6c6a7293af88d3d74576e5c839e7b77f129631379b34821484022fc99553',
 'cli-queue/compact/unclaim_recovery_required/text': '636f84cccdf6fe46b4739436788b79df30591b1d9cc13ac6ef149c12408cdbdb',
 'cli-queue/compact/unclaim_recovery_required/json': '636f84cccdf6fe46b4739436788b79df30591b1d9cc13ac6ef149c12408cdbdb',
 'cli-queue/compact/queue_lock_timeout/text': 'd6b8163cff25a2506ddf90a9b2cedb3807c15df49b88f1d69b051456c4f7f53b',
 'cli-queue/compact/queue_lock_timeout/json': 'd6b8163cff25a2506ddf90a9b2cedb3807c15df49b88f1d69b051456c4f7f53b',
 'cli-queue/compact/queue_history_limit/text': 'c35fc4569e1aefbceba7fe993b8135d73e19f67c19e6fa7421ff732ae5c38acf',
 'cli-queue/compact/queue_history_limit/json': 'c35fc4569e1aefbceba7fe993b8135d73e19f67c19e6fa7421ff732ae5c38acf',
 'core-queue/add/valid/dict': 'fe60c6c01c8f5adeaa653e6bf7a8fc21258ce0c4da7c1faeec909b181a56e5ff',
 'core-queue/add/oversized/dict': 'c2aaca8303ced6f13183913e60e5e2acff94b108d0d0fb45f609a28ed61c12d1',
 'core-queue/add/invalid_arguments/dict': 'c2aaca8303ced6f13183913e60e5e2acff94b108d0d0fb45f609a28ed61c12d1',
 'core-queue/add/invalid_queue_state/dict': '36bdeb232103e9f988b24e8647c78c018824c8119e8dac18a1eb0a17c078a55f',
 'core-queue/add/queue_size_limit/dict': '422b1424cbf27a5da29c09f5480682bab8a32c8b489f8e005720469b327bd0b3',
 'core-queue/add/unsupported_platform/dict': '9046b2c94b44085f9dd65236e0015aefaeeca254e4e5683d2277166ec8c8a76d',
 'core-queue/add/queue_io_unavailable/dict': '076be5182905950e062bf745ec3d9c9d24717b027c6ec8b2ed07b0e09b160767',
 'core-queue/add/unclaim_recovery_required/dict': 'fb9e6b25c1cf24c437e58259cc22c938d37b351b0ba8cc288e080b79807c29b6',
 'core-queue/add/queue_lock_timeout/dict': '1176100526574bbe097182b0b3fdc31cc5748a8db5545c6bcb596eee786e7f84',
 'core-queue/add/invalid_item/dict': '4ded2a9c4ea3bc2827f832e505bd40a54d318d198d0db9d61d04a66725e598ed',
 'core-queue/add/credential_like_text/dict': 'c5f487af10bef9ce9231caf490322ae63ca4468b389a837b91517865df784148',
 'core-queue/add/brief_outside_scope/dict': '4db5f372799785ff88b334163423ca05162fa6d730728c8ea20a22f29696578c',
 'core-queue/add/item_exists/dict': 'd2522f7ca2d46e5fa8dee2fa86b068130d317d5f86832ec43eb49d36d17d2ce5',
 'core-queue/add/queue_live_limit/dict': '22f5e94f8ba4963bd2045c3a6e4b2e48c902267bbee116902b0ecc57ebe247c1',
 'core-queue/list/valid/dict': 'e2aa77edee7605b2f5f54574234c15e21e2a0eb6d65523fe65f323751726eb5e',
 'core-queue/list/oversized/dict': 'e9cfd20e68d06f89e8546bc25b51e4f83b06c7be5678657d65e0d836348373f8',
 'core-queue/list/invalid_arguments/dict': 'e9cfd20e68d06f89e8546bc25b51e4f83b06c7be5678657d65e0d836348373f8',
 'core-queue/list/invalid_queue_state/dict': '937a3e6369c5979848a9b33b136117a285b0da9c535d4acf6c8000ba37c16159',
 'core-queue/list/queue_size_limit/dict': '1cb9ecbdbe5436122633800ec39e79fc59e72cdc1fefb190093ebe10e6dc279b',
 'core-queue/list/unsupported_platform/dict': '28c8057c096ff42602b497058bc754987f7accd6da49937c3908f057e3d62b74',
 'core-queue/list/queue_io_unavailable/dict': '4b305060eb0acb7ee5f98f87d2e7470f05191f720c2fe51ef1c1fa0e41deb31e',
 'core-queue/list/unclaim_recovery_required/dict': 'e9b3f8ea00e0ce97f06f7cc7dc171d6f8ff0a79482182a9809fb2f768b577c5a',
 'core-queue/list/malformed_capability/dict': '53f5598604c932505815550cd9c4affb30c6c0c2913dc7e6ccf05fb0de26d6cc',
 'core-queue/claim/valid/dict': '61fb2b965c21d5253358ad827146f8fa098e96107383b79a6a57a93f701580f9',
 'core-queue/claim/oversized/dict': 'f0ce39215e2d0a7bea16ea2c3b435ed98752a3252eee696e5b176bca2876ccd7',
 'core-queue/claim/invalid_arguments/dict': 'f0ce39215e2d0a7bea16ea2c3b435ed98752a3252eee696e5b176bca2876ccd7',
 'core-queue/claim/invalid_queue_state/dict': '811097086c4cb3960c20a62e96fa920ae631ccaf80eab88bc1496aa7a0483030',
 'core-queue/claim/queue_size_limit/dict': 'a7feb4499d39dc0fae5b217db4d463f0adb1c489a175a846dd28ad623f1c6159',
 'core-queue/claim/unsupported_platform/dict': '66bf00fd466720cc01526a66deed38bd2bb8d7b1301aa3e7fe7ed14b501a548d',
 'core-queue/claim/queue_io_unavailable/dict': 'cd0f825a901ff47b4c6eefadf62c9f105fc7e0902a28a7a72d015474033cd2aa',
 'core-queue/claim/unclaim_recovery_required/dict': 'a23905a0c892722c7f80d6c9989e910f8d8199544c5fc68c102b08c2e070b344',
 'core-queue/claim/queue_lock_timeout/dict': '7739bdc289ed6886be4312eb5203ecc618159b385db2564aadd1cb03c929d4eb',
 'core-queue/claim/item_missing/dict': '85cf7a4a7babacd5224dc12334cbb6302f60f6bc33d3a3667f4cc74b1f58656d',
 'core-queue/claim/stale_revision/dict': 'd14544c058b8556442703607c63beda479c1dbb4b959c0bec38ff1a1d52b78cc',
 'core-queue/claim/already_claimed/dict': '2b729b4890fefc7a599e4b15c7bc24e310b90cdd2f7623e9477d2fd67b15efb5',
 'core-queue/claim/lane_busy/dict': '499ec0798577cae32f1b9e8e46e3373d6aa54c790616c007e81a3c495e75bf77',
 'core-queue/claim/capability_mismatch/dict': '1423c5554cc2c4a156a64facd10ab8e230f968fa7b8070834bffb80f2be422a5',
 'core-queue/claim/blocked/dict': '6bfe925d5d77c4c441e8e14dc22bb378bb3b1d803555637767b399479875c522',
 'core-queue/claim/profile_unavailable/dict': 'f3be0382a02825f69514c9f0bd12fa9a1659e4d79f7c43ac8a5115dbf0f47f1a',
 'core-queue/claim/capacity_full/dict': 'f2624cccec766f0096839c390a31f9caf1aa6a6c64bc458c1131f01241a94d58',
 'core-queue/claim/item_done/dict': 'c483155ed60f67b9d2bcbea8305aa61712672f8814deb3868536c8292e8c9812',
 'core-queue/claim/malformed_identifier/dict': 'f0ce39215e2d0a7bea16ea2c3b435ed98752a3252eee696e5b176bca2876ccd7',
 'core-queue/claim/malformed_revision/dict': 'f0ce39215e2d0a7bea16ea2c3b435ed98752a3252eee696e5b176bca2876ccd7',
 'core-queue/release/valid/dict': 'a332c486d97e886e7c2318c7ab19583d42db77078c82ff2fee81c55a773b7a0b',
 'core-queue/release/oversized/dict': '783f942711092278a3cbfc766a33f9729a2b4df21686125f4006e2c4f7794bc8',
 'core-queue/release/invalid_arguments/dict': '783f942711092278a3cbfc766a33f9729a2b4df21686125f4006e2c4f7794bc8',
 'core-queue/release/invalid_queue_state/dict': 'ac56c1f08d0a1177751b88830d5fb35440433872805f7a91643012c276479636',
 'core-queue/release/queue_size_limit/dict': 'a5c0dad600c7cc498ae3e40b82e987454f67eefe687fddc2361ac93f979f132c',
 'core-queue/release/unsupported_platform/dict': '6538f2912f2a97e0c51f5cd9af5756995096937c6387c28d0ff7de441291f405',
 'core-queue/release/queue_io_unavailable/dict': '601d21284be47d94ddcb2f90b9e1338da2fa162bc9ac927f95b4e9741e256ea2',
 'core-queue/release/unclaim_recovery_required/dict': '265a5d1740bc8044625f06e33ee7a718ac18fefa922742d80fa1c1425c95e717',
 'core-queue/release/queue_lock_timeout/dict': 'cf698dfdd97abbfeedcf9a867995273ccac64e2eb59f655871cd05d1aba9b26e',
 'core-queue/release/item_missing/dict': 'bfba77d4480e22d080aec23200025ea0bc53bec2665c77927400a70953c15cd9',
 'core-queue/release/stale_revision/dict': '3039ef59fd14380142132480af7d41b99e25022f6bcfba2feac53ac911ae5c7f',
 'core-queue/release/not_claimed/dict': 'f885827072cb86a2a8e21cd450b644cc3722e8617890c1b16aa26181622a36f3',
 'core-queue/release/lane_required/dict': '5ca45d0667901561fb9239e3d3e6b97aac93e0109c04a805fddf7662318049cf',
 'core-queue/release/lane_mismatch/dict': 'ac6b750f6439aca59d642aea4fb4aa9b85d19905e84abdbf854644e52d4bda43',
 'core-queue/release/item_done/dict': '15a169496d59bdead2a22d8e16dc938f879a64d649e6de18154ca3aacbe50aa0',
 'core-queue/release/malformed_identifier/dict': '783f942711092278a3cbfc766a33f9729a2b4df21686125f4006e2c4f7794bc8',
 'core-queue/release/malformed_revision/dict': '783f942711092278a3cbfc766a33f9729a2b4df21686125f4006e2c4f7794bc8',
 'core-queue/unclaim/valid/dict': 'd625e2e8a2231321c8df1dbe3d98d62a2f469b9c959b28dcd7e0c8a1ce27e981',
 'core-queue/unclaim/oversized/dict': 'a1d1e6bbf34e1f0a11d037ce28ef359b528569dcda040d25941dcc7d2d2ee24a',
 'core-queue/unclaim/invalid_arguments/dict': 'a1d1e6bbf34e1f0a11d037ce28ef359b528569dcda040d25941dcc7d2d2ee24a',
 'core-queue/unclaim/invalid_queue_state/dict': 'dbd06f15947bc203cf16824787f342d875f619e7edab38ded52203fa313bb6f5',
 'core-queue/unclaim/queue_size_limit/dict': '0e84e1320da05f0ea3bc26c2427f4d2fb4bb5d8205d8e16057e7db95442eab98',
 'core-queue/unclaim/unsupported_platform/dict': '167ea7453eb1b2208e17da2655d0d47349f0dc89bed3f65a49462e055de4cdfb',
 'core-queue/unclaim/queue_io_unavailable/dict': 'f0475ed9e2ab8d95388a5adbe4f7937fd1ad383264c7fc984645e444186a4797',
 'core-queue/unclaim/unclaim_recovery_required/dict': '0b5f3900beda42379bf4c3f533d7831fa1e10d6e8cc8a76087a223dbfd183935',
 'core-queue/unclaim/queue_lock_timeout/dict': 'd21cc1117bcbc9141d081ae2acc629889bc12deeddbf91802a99248dc1271d07',
 'core-queue/unclaim/item_missing/dict': '2049cf09e3756e1ade4b6a7fd4a1dafa0d921ae9449627205d59a0e58f78b714',
 'core-queue/unclaim/stale_revision/dict': '317b984d6ba9db6fad5a83ea7ab83116874fbaa8d1741bfb86e2a4e02d4fe0c7',
 'core-queue/unclaim/not_claimed/dict': 'ce081c1565218fed8abbad661f50b91fc014eb5a4f15c97d9c61c25d451784f1',
 'core-queue/unclaim/lane_mismatch/dict': '682fb4c94b7ca61254df331cc8412d6b129ec54781e3b3cd15af02ed29a2fa44',
 'core-queue/unclaim/writer_not_stopped/dict': '8df21067e1acf192e8552d2394a91169d6bfd02ca51fc78202fa25b6e9ae1a40',
 'core-queue/unclaim/invalid_item/dict': '7682b940c50da9ed952866522aa9beb1756dcfd06d4596bf48144f23e273453b',
 'core-queue/unclaim/credential_like_text/dict': 'fd5ce42284f23d2176dc5feb625d98dd5067e60bf73b19eb1d321097a13435d8',
 'core-queue/unclaim/unclaim_lease_refused/dict': '7f78fbde2ffe6f4ccb2359eb7178c62dd9d6242ba463d37927a869d875eac1ce',
 'core-queue/unclaim/unclaim_event_unavailable/dict': 'a694e6bdbd419f944a80d323aee31f12a52f3bb265c07f60fb0d93086d6db0cd',
 'core-queue/unclaim/item_done/dict': 'e7be3b9f08663fac2f74e2294178117ecc53712cffa51e1d690f80a7899f6260',
 'core-queue/unclaim/malformed_identifier/dict': 'a1d1e6bbf34e1f0a11d037ce28ef359b528569dcda040d25941dcc7d2d2ee24a',
 'core-queue/unclaim/malformed_revision/dict': 'a1d1e6bbf34e1f0a11d037ce28ef359b528569dcda040d25941dcc7d2d2ee24a',
 'core-queue/done/valid/dict': 'a48a642c7f115e374f3d5b2ee97a960dd44b24b3d20c0c011e1a8aafda7c1b41',
 'core-queue/done/oversized/dict': '559465e048e06153d5303a4708f3d52ede5ea7bf6d5474267e77ab2f34a00f6a',
 'core-queue/done/invalid_arguments/dict': '559465e048e06153d5303a4708f3d52ede5ea7bf6d5474267e77ab2f34a00f6a',
 'core-queue/done/invalid_queue_state/dict': '1e4263b92b87c79508269f6f3cc275ec16f61f29edeecb222a4149a01ce435a9',
 'core-queue/done/queue_size_limit/dict': '5275a13308b631cfe193b731dbb7537c2bf6da450ba58fb5019803d32ee00d02',
 'core-queue/done/unsupported_platform/dict': '793368da2e2be43759a652f2850f579a4385e64988b85551f7fd2f952c3f32c0',
 'core-queue/done/queue_io_unavailable/dict': '15cda7ef56b8fe55f7306a9855a8a9a2733ad13fae7f59005d70630949122f78',
 'core-queue/done/unclaim_recovery_required/dict': '40c7902fe7fec1f2a6f77cb40b21fcf5442e2365e6f0447e72a84a5eafad714f',
 'core-queue/done/queue_lock_timeout/dict': '50bae5e5bff01926ed9872f688738744c84c9ba3b29a64fa7ca3fc9ad12db272',
 'core-queue/done/item_missing/dict': 'a6d1151bbf5952078f361eb73135d8011a180226c589482908f125bed1e61d5f',
 'core-queue/done/stale_revision/dict': '7b2c390a4a4aad036400ad6ed53703aea29da8fc0a64859fbe036f70960ada44',
 'core-queue/done/not_claimed/dict': 'a8e231e1c6441b089b10af8e8cab720b7fcce49bd6b0d77a4b2be3051a7ae102',
 'core-queue/done/lane_required/dict': '4051be226741d072601e5ed3f0163b6df7a08667e6335424ed86373c3fbe7879',
 'core-queue/done/lane_mismatch/dict': '3699eebee4da4266f4d1a7425b715625bc9181cbcd0af523e4e6bdd74a769949',
 'core-queue/done/lease_expired/dict': 'e9fcae4592f2c57c9e4b2342aa0ad6ffb96e6ba01943ad9a9267291689d026e2',
 'core-queue/done/item_done/dict': 'dae2b128a274edb60f22ff3748d9050f5f32e146c4e4a9d5b26cbb82dc8e5eb4',
 'core-queue/done/malformed_identifier/dict': '559465e048e06153d5303a4708f3d52ede5ea7bf6d5474267e77ab2f34a00f6a',
 'core-queue/done/malformed_revision/dict': '559465e048e06153d5303a4708f3d52ede5ea7bf6d5474267e77ab2f34a00f6a',
 'core-queue/audit/valid/dict': 'dd7cb3de450ac174558cc83d108a7026e345cb07753dc034482d2b7f9e583399',
 'core-queue/audit/oversized/dict': '03ff4b69575d432b32a08cd67bb0ae70e09547b1c362a79db7dc154c5f976ab8',
 'core-queue/audit/invalid_arguments/dict': '03ff4b69575d432b32a08cd67bb0ae70e09547b1c362a79db7dc154c5f976ab8',
 'core-queue/audit/invalid_queue_state/dict': '87c019baa6257d1f22c780858fe68fd59e4fc963aae55bb8759b9d06e64329b8',
 'core-queue/audit/queue_size_limit/dict': 'ba2f529bb06ad63ba2c893bf3c8f8331807b0c802f348578c651cf53959a1bf0',
 'core-queue/audit/unsupported_platform/dict': '7ddf6bae902ced5c30451c5bcd9c62beb80c74e0d7c2e71918268ccdef27fb3d',
 'core-queue/audit/queue_io_unavailable/dict': '1009cc95cc9349829123a6f1ed3de48ef77d139a2801a81b4911f8bd0b00b958',
 'core-queue/audit/unclaim_recovery_required/dict': '5a52f16452564837baaa7b390dcfe9bde932acca55211d1525d298b35de7b2f7',
 'core-queue/compact/valid/dict': 'd9d28429080e7e43bd5d4645d1bb79787392742f1a827e83529e3d77346277ef',
 'core-queue/compact/oversized/dict': '6336ba20cdd27c243554063b747a97b933104e39e293e5315cae3fbc78308921',
 'core-queue/compact/invalid_arguments/dict': '6336ba20cdd27c243554063b747a97b933104e39e293e5315cae3fbc78308921',
 'core-queue/compact/invalid_queue_state/dict': 'b7284de87d601465274d65de89db6acd5bec4a314245564496993f1f1be6f043',
 'core-queue/compact/queue_size_limit/dict': '69c8245416c7f690ab6ac5fc8e60fa0eef3de0a73593be63fb198182094ceb18',
 'core-queue/compact/unsupported_platform/dict': 'fdc3d060fb3cd5e8e392b892aab62ee61f1bffb0ccbbff8f42ce1e387ea8b636',
 'core-queue/compact/queue_io_unavailable/dict': '6b4c6c6a7293af88d3d74576e5c839e7b77f129631379b34821484022fc99553',
 'core-queue/compact/unclaim_recovery_required/dict': '636f84cccdf6fe46b4739436788b79df30591b1d9cc13ac6ef149c12408cdbdb',
 'core-queue/compact/queue_lock_timeout/dict': 'd6b8163cff25a2506ddf90a9b2cedb3807c15df49b88f1d69b051456c4f7f53b',
 'core-queue/compact/queue_history_limit/dict': 'c35fc4569e1aefbceba7fe993b8135d73e19f67c19e6fa7421ff732ae5c38acf',
 'lease/claim/valid/text': '29a7433b630730b10b2f93ad47d8fb7826715b8a16794e67967366afcc5300b0',
 'lease/claim/valid/json': '8fc5544232a99e57497df3cd5e3542b069f412edca5cfb1d94a12c94b0aadc77',
 'lease/claim/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/claim/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/claim/invalid_arguments/text': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/claim/invalid_arguments/json': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/claim/not_repository/text': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'lease/claim/not_repository/json': '27827bb59675f5ae9e14aafffa9e0144fb4f5cb8a81b0014398deda765d8cf65',
 'lease/claim/git_io/text': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'lease/claim/git_io/json': '7b42c66e0b94926f84f2927d4653525d2b7cd21cf7afe79c77c94a42afe371ee',
 'lease/claim/bad_lane/text': '0f63625f8052b720097c07270553730a18e00abb29baca2825e3cb0abe258a93',
 'lease/claim/bad_lane/json': '913838b46ae51b725426961210f7e2e2b878372f3ae8f4d407e13f9575c44536',
 'lease/claim/bad_ttl/text': '8807e5f1762ee6559cf68f86462e4933ada5f73b134759ffa7acaa962f68aaa8',
 'lease/claim/bad_ttl/json': '75bfc17814abdda2b9a2c484a7f275ce2345e7dcc39849af28a5d724fb47c7c8',
 'lease/claim/bad_branch/text': '4f659b2c7eb307072f5ab4e4ba069bf779735b618023358ad06c919b0ba87ba7',
 'lease/claim/bad_branch/json': 'cf85dce3522d530a2064a6431416d3008c02ea0c8dedd4a47553b2127612ce14',
 'lease/claim/bad_glob/text': 'bf76aeed39993dd6b06c2aad6f8a052b85761c528cf59f5635e2c666698f72a3',
 'lease/claim/bad_glob/json': '1d9076cae331f4488a439c2f3056975d35c191e5596279f49f03864b5754cad8',
 'lease/claim/taken/text': '768a509fce1129739a4b341065660dca2a4dade6de909de0103234e691dc94c6',
 'lease/claim/taken/json': 'db004f4aa9f328e1b156acc9aa50bbfe21bdccfcb2a852518baa3922ee4c630f',
 'lease/claim/overlap/text': 'd43d26dbd66c96fd2a137efd117783401a2d0c8f2be114782aac6d4827b55d2d',
 'lease/claim/overlap/json': 'fdde0a014c3be5ebe321499b3bb608cf2fb38b6f86a054358e8e063277166fb5',
 'lease/claim/unreadable/text': '8bc3745e6a5b1449af333dffe27e5eee999981e91323f7209a4f72336470ff43',
 'lease/claim/unreadable/json': '03e2d586afe03851e19f9bcc35ce68ece457d3ec62c8608cc44ff601abfd2e17',
 'lease/claim/legacy_paths/text': '5ad2ce420baeb6c060182b6250ac12e66e6ae2b7f73bd7366697b37396ab89a7',
 'lease/claim/legacy_paths/json': 'b98a8c5901d5df83f3ba9676a7fbdb757a06e80f236f4ddac7a9ac6b09d51b6b',
 'lease/renew/valid/text': '65b6ef445858b104e5506aaa7a4c50204b7c7c250198863463b8a77fe996596f',
 'lease/renew/valid/json': 'e4b41e6bb9b0e313052657209c84f9e92175dd3df73e6c34799eccc95758f2e9',
 'lease/renew/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/renew/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/renew/invalid_arguments/text': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/renew/invalid_arguments/json': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/renew/not_repository/text': '5eb8c567de2eb92345f530cf1160036829b0919addee75dc96304eab662df0e7',
 'lease/renew/not_repository/json': 'dd1fce331b80418446a8d2fb57de3282c84846f60ed3fb39b25c9939857b3e68',
 'lease/renew/git_io/text': '5eb8c567de2eb92345f530cf1160036829b0919addee75dc96304eab662df0e7',
 'lease/renew/git_io/json': 'c7674ff0c34fa43a86df1cf830a657059db7baede063cbcc236233960bad46c9',
 'lease/renew/bad_lane/text': '0f63625f8052b720097c07270553730a18e00abb29baca2825e3cb0abe258a93',
 'lease/renew/bad_lane/json': 'c1fb0152f10a3546279fd97240c4e51d14288f305b2b6e2dd9e34ba8f954f623',
 'lease/renew/bad_expect/text': 'd403862e4dd66e615869e6f202d91b13767f7b2e69bc2b3c052216158fad157e',
 'lease/renew/bad_expect/json': '24c2aa91c73ce43623a407da50a3baf0ad40fa0c0f2dfa878606eead93ff92c0',
 'lease/renew/bad_ttl/text': '8807e5f1762ee6559cf68f86462e4933ada5f73b134759ffa7acaa962f68aaa8',
 'lease/renew/bad_ttl/json': '55e1bfea1a17e5b0f27f181d9d2762344b6c891a4bc366319477fc2ad0b43070',
 'lease/renew/absent/text': '85c3eca4664f84406314d4349d3d4ff8533189907765acea81beec00b7b41c7e',
 'lease/renew/absent/json': 'd8ece18f7334de428769d9b51856ae67f0f61eb872ac11c688d0e64530f0edd6',
 'lease/renew/stale/text': '357670f992b6f9ade3ac139cbf8c3441012cee2e2e6927f152c587aba98de929',
 'lease/renew/stale/json': '7974043a03c179f801d87c56bfe6ab8791c68527643e7a793f131d210aace394',
 'lease/renew/unreadable/text': 'e9ae5b7b2732dcfd0aa3bc679956e757bc39d1005c444ee6c4d6b1ac2c06684b',
 'lease/renew/unreadable/json': '996fd5c7c42d6e1cc4c007a38cafdc4be8cce5ef8723c37fba32dce6050f9550',
 'lease/renew/legacy_paths/text': '042eec0fe2a784ec63a28e42a3f7a6d5579ba194eb5949086bfba29de8e610d5',
 'lease/renew/legacy_paths/json': '75b9808cb0a7906d54f2b00dda0a78735bd97e14ac4506f07986d64d05b4e4da',
 'lease/renew/overlap/text': 'd43d26dbd66c96fd2a137efd117783401a2d0c8f2be114782aac6d4827b55d2d',
 'lease/renew/overlap/json': '647cb05945388bf8bb8cbac7158fdf055401c8b782b6711878f88fb20a4ec5ad',
 'lease/renew/lease_branch_missing/text': '0715ef45e961c5a713fb4c35557570d044f99ee000661edcd40c0c066efb007c',
 'lease/renew/lease_branch_missing/json': '44fef522ab1cf9140a7543178fe1af58a91c931f7d9577c8a83ada41a71b7b01',
 'lease/renew/ambient_git_environment/text': 'e81e14f1289b80c16f220afde4623219949648c83e7b8dfedf04baa338f75bdd',
 'lease/renew/ambient_git_environment/json': '17cc25e996203aa8121e0bbee08e72b3c127e0352d24d80c3106aaedac69a7d3',
 'lease/transfer/valid/text': '63f17ca024f7e2f4e71bf67a32ba41417d735f4a8cfcfc3aab4f1b1a8a54decd',
 'lease/transfer/valid/json': '24798401e162f8a8a6a1fb4b2ee48ab531b5a1b9f4e15362f07564d7ab341eb1',
 'lease/transfer/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/transfer/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/transfer/invalid_arguments/text': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/transfer/invalid_arguments/json': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/transfer/not_repository/text': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'lease/transfer/not_repository/json': '07af86cce208a5dd74c63ea83acc388eea44640c1cadf3a6610423fe4e9baf32',
 'lease/transfer/git_io/text': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'lease/transfer/git_io/json': 'abaf5e60673297eff71ce79edf112b1fc5184e67da4257cd8471d7962ae6545e',
 'lease/transfer/bad_lane/text': '0f63625f8052b720097c07270553730a18e00abb29baca2825e3cb0abe258a93',
 'lease/transfer/bad_lane/json': '66d658437cda01e0ceecba8febdad2f9d5a372e62341953911f2f9f50bc372f2',
 'lease/transfer/bad_expect/text': 'd403862e4dd66e615869e6f202d91b13767f7b2e69bc2b3c052216158fad157e',
 'lease/transfer/bad_expect/json': '9fb620b752e21a26beacde29f1a62fb8a9806ff28f2471cecc3dec636888aca8',
 'lease/transfer/absent/text': '85c3eca4664f84406314d4349d3d4ff8533189907765acea81beec00b7b41c7e',
 'lease/transfer/absent/json': '5de26e794214dfce1e9de9bf40182b93f2a96f9c457db70078995030712851e7',
 'lease/transfer/stale/text': '357670f992b6f9ade3ac139cbf8c3441012cee2e2e6927f152c587aba98de929',
 'lease/transfer/stale/json': '06f4ab962d0d88afc4b0d16ea213402a27bc747f453898aa7af7ad967aeb0544',
 'lease/transfer/unreadable/text': 'e9ae5b7b2732dcfd0aa3bc679956e757bc39d1005c444ee6c4d6b1ac2c06684b',
 'lease/transfer/unreadable/json': '4ee337c8823f1359fa3d1e9de59e3c1479eaf778635e807fdba875627e5ae364',
 'lease/transfer/legacy_paths/text': '042eec0fe2a784ec63a28e42a3f7a6d5579ba194eb5949086bfba29de8e610d5',
 'lease/transfer/legacy_paths/json': 'e3b2a03b6f32959896771ab7310e2b634686351ee63742c93553c8e9194417fc',
 'lease/transfer/expired/text': '62c70a343a65d6eb58270b3fc9ce1ff07c44a345dbd1b4f98a0a1add2360e4dd',
 'lease/transfer/expired/json': '6056226bb2aaf1850fbb1445fa44cb1596d0ad9e5a1fd4b1683897023b923423',
 'lease/release/valid/text': '29d7995786ff520590dc58496b7c2e677d983e23f03e10cb45abeae705086922',
 'lease/release/valid/json': 'c5fba34e8ae403bc08c45d2d1399b5bf4c7b5608483e35654941ea14603e8cb1',
 'lease/release/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/release/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/release/invalid_arguments/text': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/release/invalid_arguments/json': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/release/not_repository/text': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'lease/release/not_repository/json': 'a96c5e1e74e00980b1d8fa3f98109b2d0854b353b36ef0b1c2f85f1fd2259247',
 'lease/release/git_io/text': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'lease/release/git_io/json': '7fc7cc6c8ba88e439453a6607ad8aae04ab57d8d9ff0c4f13e1ea80765dabb04',
 'lease/release/bad_lane/text': '0f63625f8052b720097c07270553730a18e00abb29baca2825e3cb0abe258a93',
 'lease/release/bad_lane/json': '8304e4af7eacf1951f158c44a0f6a9c7f0f3d1ca055136b1d33fff9838b58d8a',
 'lease/release/bad_expect/text': 'd403862e4dd66e615869e6f202d91b13767f7b2e69bc2b3c052216158fad157e',
 'lease/release/bad_expect/json': '6f4afcc6245e04b8128b20757a8d3589505124dc48b66402c0f890792ba990f0',
 'lease/release/absent/text': '85c3eca4664f84406314d4349d3d4ff8533189907765acea81beec00b7b41c7e',
 'lease/release/absent/json': 'cbf365352959c6e95d815160bbe9126b06378e4c060b0433d31c0fca985ebadc',
 'lease/release/stale/text': '357670f992b6f9ade3ac139cbf8c3441012cee2e2e6927f152c587aba98de929',
 'lease/release/stale/json': '9b57ef253f3440f49f4991ab7895d7977637a3d4ec644f27d5a76263676d8222',
 'lease/gc/valid/text': '5146ce591942cf1d48e7d6d4e3556ced4a5436a4a08f629b074ac6b288e39353',
 'lease/gc/valid/json': 'f191ef007b4434baab5616354ebc81012775f1c63f1db3bf9bf6df4cb3d07298',
 'lease/gc/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/gc/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/gc/invalid_arguments/text': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/gc/invalid_arguments/json': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/gc/not_repository/text': '5eb8c567de2eb92345f530cf1160036829b0919addee75dc96304eab662df0e7',
 'lease/gc/not_repository/json': 'bff937951fd06d909691fec5601f796b5b6a554ea7f26d2a2361ad3d1abc6e67',
 'lease/gc/git_io/text': '5eb8c567de2eb92345f530cf1160036829b0919addee75dc96304eab662df0e7',
 'lease/gc/git_io/json': 'edbdd9d2bb1f8d2a63ebe9e670aafaafb8be76ec012ce817ef7151955f8e5206',
 'lease/gc/ambient_git_environment/text': 'e81e14f1289b80c16f220afde4623219949648c83e7b8dfedf04baa338f75bdd',
 'lease/gc/ambient_git_environment/json': '3b45e8660b707b5e2a1717d2a2e65f089c49c11074512b7f0330e85426eacdc4',
 'lease/list/valid/text': '698c39ce3d2a0f4af9339c274d50aed6c28bd7790b611e060fd5e8ffd0fdf3b3',
 'lease/list/valid/json': 'edcb414811eb771b6857fe5297ed918449d30e8d96c84290ad92c0c88736f076',
 'lease/list/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/list/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/list/invalid_arguments/text': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/list/invalid_arguments/json': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/list/not_repository/text': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'lease/list/not_repository/json': 'b478667d1bdb9af80b2ffcfd2dccd35d89b36af5a91ef46980c4df7141e17c01',
 'lease/list/git_io/text': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'lease/list/git_io/json': '33ca24d22f75eddcd4ecd4e445dfba614f57ac224723f00f0c0922db4b62cdcc',
 'lease/status/valid/text': 'fc3cad1ed226801b6bb9c9b83883cf2b931c22df0fdeceb8857a263ed07f6d45',
 'lease/status/valid/json': '71e77b9349f2cac33f6c3e4d25430b0467e97fb0cbe8e70cd05555a41081fe34',
 'lease/status/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/status/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/status/invalid_arguments/text': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/status/invalid_arguments/json': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/status/not_repository/text': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'lease/status/not_repository/json': '2fe703d80841a104cb8525b57704046ce6cb340205e6bd43afba23b5f1357e80',
 'lease/status/git_io/text': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'lease/status/git_io/json': '61f86167b72a7a7151678d206d3d495fcd7ce3a150ab82567551b76e5302c55c',
 'lease/status/bad_base/text': '2f9961cab8771e7aa02955d76c6a7572c1c9e6445d44d7efb07f87371024b63a',
 'lease/status/bad_base/json': '0709dea5f3d26915a782cfa332ce52089a9cb8efd0ba4317358832f4378ce6a4',
 'lease/metrics/valid/text': 'af588a008a5658514bd7b908dc9ffe6c78fc721ebe28a3362bbc611d3c1f1c48',
 'lease/metrics/valid/json': '964da3fff4c9b1dcd8dcd7ad9260c1b4a3d21e6bc7a1354a0214e181ea17a6f5',
 'lease/metrics/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/metrics/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'lease/metrics/invalid_arguments/text': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/metrics/invalid_arguments/json': 'ab3ce0306fdf22b1defb7ef22f3b6102177138d008ea9ec1499a4058db91d65a',
 'lease/metrics/not_repository/text': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'lease/metrics/not_repository/json': '86553f31a1b00b057819eba1ae5083fd8c69b8a7f9091ee0084f60bd5529e430',
 'lease/metrics/git_io/text': '0943e2b8aa834a5168385cfe190d9b2d8ca501b916515f74227133d6c3062a28',
 'lease/metrics/git_io/json': '8d3c09eba6f6316813f90c08a12522af0e0da0bc33e9753a01e10f0487a1c375',
 'lease/metrics/bad_base/text': '2f9961cab8771e7aa02955d76c6a7572c1c9e6445d44d7efb07f87371024b63a',
 'lease/metrics/bad_base/json': 'a219c6eb6f961428b6e5e3edd3a4d841d1c93fe709190dade36af1fac7df7516',
 'model/model/valid/json': '651ea06febcd5bbc3dd2418d7ee6d80875d7301f132c6b159b6d047c8b40d261',
 'model/model/record/json': '651ea06febcd5bbc3dd2418d7ee6d80875d7301f132c6b159b6d047c8b40d261',
 'model/model/oversized/json': '2b4af3ad53a126fd7adcfde8b27b9ef630e1b80339d94211e2cb21b92bd1fc91',
 'model/model/invalid_arguments/json': '532200670f8b5b09d6cb0987738defddab0a924ff678f6403a80207f5079c450',
 'model/model/missing_bindings/json': '11f9197f7d9d8468ee4f22c3772ed47cf385f476443432b12511766a52dbc461',
 'model/model/invalid_bindings/json': '11f9197f7d9d8468ee4f22c3772ed47cf385f476443432b12511766a52dbc461',
 'model/model/invalid_policy/json': 'd7fcbd9683bf269cf5a2b1932484550033eeb5e5e868bbfb4753e99c4f17777c',
 'model/model/invalid_history/json': '6b30333dfa5e099c8e45da8f464b6d74be502ae26edfa87bd3752737ff5c3adf',
 'model/model/unknown_task_kind/json': '4c1c16f4b58a11243a332e145f626c8480df56bc2dc16bade3d87626ecbe9109',
 'model/model/unknown_role_kind/json': '84a643a90e629ba92f0565f488a095b7164a8126edb4acfc2682ec7f5a963016',
 'model/model/task_role_mismatch/json': 'e1ecb4addfd74f7be0a485047b0c44f8f026b2479ec8a2a5459ef745c349fc5d',
 'model/model/invalid_subject/json': '79000414d180daf1a170ad0b24820d78d363f8d42891beba67dd573cdf1472d8',
 'model/model/unknown_intent/json': '36d1247e59fa57035999099b86ceeb674db4efea3ddc201dc80a593feecf085e',
 'model/model/invalid_author_family/json': 'aecac0711f289e6410447ed986a2c01091e953ab8cb6d1b467f94f38522c3885',
 'model/model/invalid_lane_family/json': '22d4d8e22b701075959a6424b9462bf05b08cfff7797c074a28803e0adf3fb38',
 'model/model/invalid_review_stage/json': '267c27986d93dcbaa94152e0e40019e9172ec042d07ee5749b012a014f0778e3',
 'model/model/binding_unavailable/json': '6ff811c0d011c5db80871d48bd6fd4a855f939b5ba08d438e9278ac5ddb8b32f',
 'model/model/unadmitted/json': '04d0d63779585cd6a9e8adbf48f545aef055f31f993a5e777256cf0959032185',
 'model/model/model_output_needs_redaction/json': 'ad646ac80b6bcc739f5252e1fb3c7995e401bbe17c54b808174f29aa6280f2ce',
 'model/model/model_workspace_unavailable/json': '2b4af3ad53a126fd7adcfde8b27b9ef630e1b80339d94211e2cb21b92bd1fc91',
 'model/model/model_lock_timeout/json': '3deeb880af33bf8a706b75fe81c2f680f8b70abebff14128b1b5bf03d7d8fbf9',
 'model/model/model_io_unavailable/json': 'b5245e191ce5ed3c937ce9a32a6664b92d6cde34043b0e30228a25f9138c3bf6',
 'model/model/intent_outside_role_band/json': 'af888e119af74fceb5aab38f65dff2049ba30eba12061e052f5aa6815d080616',
 'model/model/lane_family_mismatch/json': '891d351fdeb943eb1c20f823ae2fc6933bc4bab227c58210c6a81d25c1b1fa03',
 'model/model/unsafe_path/json': '532200670f8b5b09d6cb0987738defddab0a924ff678f6403a80207f5079c450',
 'model/model/oversized_arguments/json': '532200670f8b5b09d6cb0987738defddab0a924ff678f6403a80207f5079c450',
 'model/model/invalid_log_path/json': 'c30e6ffbce46a6004f66e8640c4ca90db3b6bb080327f0f456586178c154fab3',
 'model/model/unsafe_decision_path/json': 'be12f30b66871710b0f8fcb0bf552a1960782f84d931b5f828ab4a4959206ca1',
 'model/model/unsafe_decision_directory/json': 'b21640ca384bba818b079bae91e92c0b8daec9b5c729d3c5c330801a1e5cae5c',
 'model/model/anchored_io_unavailable/json': '20acfb6681218f39779107fda86d2e80de4d622896dc957dc01fc89aa92ae8a2',
 'core-model/read_decisions/invalid_log_path/exception': '7b265a7dad2cb7c72e3d4f41d1b7dab9ebc021a59d60129623ccc8f249d8d7ef',
 'core-model/read_decisions/unsafe_decision_path/exception': 'b10091e2f4fbf7b1f1cd47d41e734c175ed8d03b06e9fac5aa2e0256c26ef181',
 'core-model/read_decisions/unsafe_decision_directory/exception': '47aa7b001f239ae2ac631ce4babcffd66a4cb0fbc76d91956b985a376d63a1b3',
 'core-model/read_decisions/anchored_io_unavailable/exception': '1c71966cc36de8449e78b769c9fe01875489c82c3545b90b6c0be591acdb3998',
 'msg/write/valid/json': '6a1d49f249294e4bbf5f302e9c4a05823a2569e3c1e3077c9de42f6b97593bb1',
 'msg/write/oversized/json': 'fc5a42196401a2e6f637f03c9cff3f5b04f9f5b7b94b9d59c2bdc5b754692812',
 'msg/write/missing_input/json': '73aa5c72f1840b6dd81885de69b7d955277b110305880d46a87272af5219d600',
 'msg/write/invalid_json/json': 'ffe36d2222d43171743be28964d81954ee8a0a7b3e39c09fc37cc806ca3855b7',
 'msg/write/invalid_fields/json': 'ffe36d2222d43171743be28964d81954ee8a0a7b3e39c09fc37cc806ca3855b7',
 'msg/write/large_input/json': 'd8c8c53e94acff63376843d450acda5daffa38aae60266783aa8ef722abf9736',
 'msg/write/missing_ref/json': '96b6fe21203cd3569c6befc2a9b79db9b4566c122894ee834f91d9f7c6899257',
 'msg/write/unsafe_store/json': 'd83be425b161695af6698fc77a3924fd6c40ea51aeb361041b637f032b834177',
 'msg/write/unsupported/json': '976ce16c911133889767fae77ab8fed7565f5c43cb42b8b4a27ef412dca38968',
 'msg/write/io/json': '5d29360e7557f29ade7744a785e9ab1d0ba66d50118fdd08bba4588370f7a60c',
 'msg/read/valid/json': '154b8124d2de93de0cbba27c16fa78b89e4a912c3855789f5b735d9e0a365f37',
 'msg/read/oversized/json': 'fc5a42196401a2e6f637f03c9cff3f5b04f9f5b7b94b9d59c2bdc5b754692812',
 'msg/read/missing_ref/json': '8d3969fbf036759829420aa437179422d104d09e622f8c9c5aff9df78ba998db',
 'msg/read/invalid_ref/json': '51ec2448cbf5956ca3849b8921c5ef7982363bbbf553555626539121b6cac50e',
 'msg/read/hash/json': 'a0379644a8b7f0a5c9544d3ff6d59da37cc4f2bae607002ea633b34f38e9bcc0',
 'msg/read/selector/json': '75f54e9380937123b2fc156d7e8730843dfded58d0ee89e3fc5e34dd3195f73d',
 'msg/read/span/json': '985e2cf4b160ba41d53b832578c7d54bc787c52f63eca7c8603bb719e129fff5',
 'msg/read/expand/json': 'c0d5e761c60cee0e2248d185fc23e6ba5df22c8804a4a9693842c281b7129cde',
 'msg/read/limit/json': 'd1ec8b5c79bbeb0d6820274968af74c9c647c0b0df20e38b3eb4176701ad34be',
 'msg/read/format/json': '0e57d10b7af997d816d899cec5c07b3e00631d8a8fd85ce1e1d9676fa588beeb',
 'msg/read/unsafe_store/json': 'd83be425b161695af6698fc77a3924fd6c40ea51aeb361041b637f032b834177',
 'msg/read/unsupported/json': '976ce16c911133889767fae77ab8fed7565f5c43cb42b8b4a27ef412dca38968',
 'msg/read/io/json': '5d29360e7557f29ade7744a785e9ab1d0ba66d50118fdd08bba4588370f7a60c',
 'msg/verify/valid/json': '4c68f45db2399e240b37d00319de667e2b63880573220c491b880dd40f93524d',
 'msg/verify/oversized/json': 'fc5a42196401a2e6f637f03c9cff3f5b04f9f5b7b94b9d59c2bdc5b754692812',
 'msg/verify/missing_ref/json': '8d3969fbf036759829420aa437179422d104d09e622f8c9c5aff9df78ba998db',
 'msg/verify/invalid_ref/json': '51ec2448cbf5956ca3849b8921c5ef7982363bbbf553555626539121b6cac50e',
 'msg/verify/hash/json': 'a0379644a8b7f0a5c9544d3ff6d59da37cc4f2bae607002ea633b34f38e9bcc0',
 'msg/verify/unsafe_store/json': 'd83be425b161695af6698fc77a3924fd6c40ea51aeb361041b637f032b834177',
 'msg/verify/unsupported/json': '976ce16c911133889767fae77ab8fed7565f5c43cb42b8b4a27ef412dca38968',
 'msg/verify/io/json': '5d29360e7557f29ade7744a785e9ab1d0ba66d50118fdd08bba4588370f7a60c',
 'profile/config show/valid/text': 'bb7abd39a7839d62a7b5af2c597c4e512747e8d48a8706d48c9a395c6e7b9de9',
 'profile/config show/valid/json': 'bb7abd39a7839d62a7b5af2c597c4e512747e8d48a8706d48c9a395c6e7b9de9',
 'profile/config show/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'profile/config show/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'profile/config show/invalid_profile/text': 'e9d9d54c2c7b942a6a90de408b3c2159deca4b0d410e8ec91ded122d2dfd4032',
 'profile/config show/invalid_profile/json': '96b87127c116032bd258f33c54db99137185a587fb9978a8d96709dfa7ad6ca0',
 'profile/config presets/valid/text': '95009f06d74e498b53fc3b35039f5b9b0c527465edac9260a2a9f8dc75a1ffdc',
 'profile/config presets/valid/json': '95009f06d74e498b53fc3b35039f5b9b0c527465edac9260a2a9f8dc75a1ffdc',
 'profile/config presets/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'profile/config presets/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'profile/config init/valid/text': '8bb41f0d2c830642d86e7504731898ff941441cb524617dfdcf2bbd1eb2e87f4',
 'profile/config init/valid/json': '8bb41f0d2c830642d86e7504731898ff941441cb524617dfdcf2bbd1eb2e87f4',
 'profile/config init/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'profile/config init/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'profile/config init/invalid_profile/text': 'e9d9d54c2c7b942a6a90de408b3c2159deca4b0d410e8ec91ded122d2dfd4032',
 'profile/config init/invalid_profile/json': 'e0e59ccd3c8f001e534a891573e1541b10cb7f61597fa630ac4e761aa4655715',
 'profile/config init/exists/text': 'fbbd5d61643a1afa2d90666b8946a1611fc4c59d6c91afd5e1b107c6b25642b2',
 'profile/config init/exists/json': '88bc158b2ded2a06a142d4543bd7ec30f8df8209a783462cc99734b840226da3',
 'profile/config init/invalid_preset/text': '0a81ed15e94b1fac347b32f7aa5bbeb1431871e56cc3015d9ac6cd6803352f0f',
 'profile/config init/invalid_preset/json': 'f49bffa1cbfd61c5eaed3492327b845ba675dc5c994b274122ca20b1bf373854',
 'profile/doctor/valid/text': '85cd792c30c6e66b5147e48315d3edbccf24a3eca38dee1cf5607d4ba0653df8',
 'profile/doctor/valid/json': '85cd792c30c6e66b5147e48315d3edbccf24a3eca38dee1cf5607d4ba0653df8',
 'profile/doctor/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'profile/doctor/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'profile/doctor/invalid_profile/text': 'e9d9d54c2c7b942a6a90de408b3c2159deca4b0d410e8ec91ded122d2dfd4032',
 'profile/doctor/invalid_profile/json': '1cac099d0a2537980f3585919c9e4221094125e641c3d6b27caca620825027e5',
 'profile/doctor/missing_cli/text': 'e96173f1ebc174bded29f78c818aa8ff414b18635b5b137083c70004ea72eec7',
 'profile/doctor/missing_cli/json': '4b9139b8b2741c2040ee71f95a8b8fd10419d6ad0b57fd4c780ebcd02f392777',
 'profile/hosts status/valid/text': '9a23c9a3d57b8612c9d897be57c55d86a1245f5f612f05acbd877031e5e6bbcb',
 'profile/hosts status/valid/json': '9a23c9a3d57b8612c9d897be57c55d86a1245f5f612f05acbd877031e5e6bbcb',
 'profile/hosts status/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'profile/hosts status/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'profile/hosts status/invalid_profile/text': 'e9d9d54c2c7b942a6a90de408b3c2159deca4b0d410e8ec91ded122d2dfd4032',
 'profile/hosts status/invalid_profile/json': '359fea36a059e13ccacd2dd43926d7b5f02a0addee98d08a72504bc6649172e5',
 'profile/hosts usage/valid/text': '984cc8e55d0dbbd432c6ebb8843cb0b07b9068411b41a1f94c10047108a869ef',
 'profile/hosts usage/valid/json': '984cc8e55d0dbbd432c6ebb8843cb0b07b9068411b41a1f94c10047108a869ef',
 'profile/hosts usage/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'profile/hosts usage/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'profile/hosts usage/invalid_profile/text': 'e9d9d54c2c7b942a6a90de408b3c2159deca4b0d410e8ec91ded122d2dfd4032',
 'profile/hosts usage/invalid_profile/json': '194dadd4871ab1871ef3872582d23764401403657f418f294fef91e27908fb44',
 'profile/hosts check/valid/text': '9faafc3f36cbf7e89217bb464162b2dfe510f606b0117d8c9e854af61c482d3f',
 'profile/hosts check/valid/json': '9faafc3f36cbf7e89217bb464162b2dfe510f606b0117d8c9e854af61c482d3f',
 'profile/hosts check/oversized/text': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'profile/hosts check/oversized/json': '8902de7d0dc899f5f8fe1ba099b3ad8bd16e42105c8533e9af2650dc9ad37e3d',
 'profile/hosts check/invalid_profile/text': 'e9d9d54c2c7b942a6a90de408b3c2159deca4b0d410e8ec91ded122d2dfd4032',
 'profile/hosts check/invalid_profile/json': '60b67a3079228fa81e4c7a62532075617112024082dc4eb6b71e2f48f98672cf',
 'profile/hosts check/unknown_host/text': '41308659e2ddcee91c98c46d11afc856cd2c44c99f934a0d8d90f6612f11fae6',
 'profile/hosts check/unknown_host/json': '57192c3b08a9cbb090aa06962fea75e4e4654d9b2be23aec758be8bd8ab2565d',
 'profile/hosts check/unknown_kind/text': '7e97cb6cd5f2de658b3b8f0de80916b4880170889d9d830315e739a3486fa8a7',
 'profile/hosts check/unknown_kind/json': 'b7cbd6517885f060a3a8236933577a0806d7061f6cf30f84a249e19368248b3a',
 'mixed/model/valid/json': '8d0ac63d07e10f0a30441b4e64d8118243af191db5c59a4e4aa4f469189f3cf6',
 'mixed/model/malformed/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'mixed/model/oversized/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'mixed/model/workspace/json': '4b305060eb0acb7ee5f98f87d2e7470f05191f720c2fe51ef1c1fa0e41deb31e',
 'mixed/msg/valid/json': '8d0ac63d07e10f0a30441b4e64d8118243af191db5c59a4e4aa4f469189f3cf6',
 'mixed/msg/malformed/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'mixed/msg/oversized/json': 'ba8f7e0d3282be2939562f05a367cd1be9b9fa507d02c11e6b5d507055e4e85f',
 'mixed/msg/workspace/json': '4b305060eb0acb7ee5f98f87d2e7470f05191f720c2fe51ef1c1fa0e41deb31e'}
QUEUE_VERBS = ("add", "list", "claim", "release", "unclaim", "done", "audit", "compact")
QUEUE_REFUSALS = {
    "add": ("invalid_item", "credential_like_text", "brief_outside_scope", "item_exists", "queue_live_limit"),
    "claim": ("item_missing", "stale_revision", "already_claimed", "lane_busy",
              "capability_mismatch", "blocked", "profile_unavailable", "capacity_full", "item_done"),
    "release": ("item_missing", "stale_revision", "not_claimed", "lane_required", "lane_mismatch", "item_done"),
    "done": ("item_missing", "stale_revision", "not_claimed", "lane_required", "lane_mismatch", "lease_expired", "item_done"),
    "unclaim": ("item_missing", "stale_revision", "not_claimed", "lane_mismatch", "writer_not_stopped", "writer_live", "invalid_item",
                "credential_like_text", "unclaim_lease_refused", "unclaim_event_unavailable",
                "unclaim_recovery_required", "item_done"),
    "compact": ("queue_history_limit",),
}
LEASE_VERBS = ("claim", "renew", "transfer", "release", "gc", "list", "status", "metrics")
LEASE_REFUSALS = {
    "claim": ("taken", "overlap", "unreadable", "legacy_paths"),
    "renew": ("absent", "stale", "unreadable", "legacy_paths", "overlap", "lease_branch_missing", "ambient_git_environment"),
    "gc": ("ambient_git_environment",),
    "transfer": ("absent", "stale", "unreadable", "legacy_paths", "expired"),
    "release": ("absent", "stale"),
    "status": ("bad_base",),
    "metrics": ("bad_base",),
}
MODEL_CASES = ("valid", "record", "oversized", "invalid_arguments", "missing_bindings", "invalid_bindings",
               "invalid_policy", "invalid_history", "unknown_task_kind", "unknown_role_kind",
               "task_role_mismatch", "invalid_subject", "unknown_intent", "invalid_author_family",
               "invalid_lane_family", "invalid_review_stage", "binding_unavailable", "unadmitted",
               "model_output_needs_redaction", "model_workspace_unavailable", "model_lock_timeout",
               "model_io_unavailable", "intent_outside_role_band", "lane_family_mismatch", "unsafe_path",
               "oversized_arguments", "invalid_log_path", "unsafe_decision_path",
               "unsafe_decision_directory", "anchored_io_unavailable")
MESSAGE_CASES = {
    "write": ("valid", "oversized", "missing_input", "invalid_json", "invalid_fields", "large_input",
              "missing_ref", "unsafe_store", "unsupported", "io"),
    "read": ("valid", "oversized", "missing_ref", "invalid_ref", "hash", "selector", "span", "expand",
             "limit", "format", "unsafe_store", "unsupported", "io"),
    "verify": ("valid", "oversized", "missing_ref", "invalid_ref", "hash", "unsafe_store", "unsupported", "io"),
}
PROFILE_PATHS = ("config show", "config presets", "config init", "doctor", "hosts status", "hosts usage", "hosts check")


def _operation_rows():
    rows = []
    for surface in ("cli", "core"):
        for verb in QUEUE_VERBS:
            cases = ("valid", "oversized", "invalid_arguments", "invalid_queue_state", "queue_size_limit",
                     "unsupported_platform", "queue_io_unavailable", "unclaim_recovery_required")
            if verb not in ("list", "audit"):
                cases += ("queue_lock_timeout",)
            cases += QUEUE_REFUSALS.get(verb, ())
            if verb in ("claim", "release", "done", "unclaim"):
                cases += ("malformed_identifier", "malformed_revision")
            elif verb == "list":
                cases += ("malformed_capability",)
            for case in dict.fromkeys(cases):
                for mode in (("text", "json") if surface == "cli" else ("dict",)):
                    rows.append((surface + "-queue", verb, case, mode))
    for verb in LEASE_VERBS:
        usage = (("bad_lane",) if verb in ("claim", "renew", "release", "transfer") else ())
        usage += (("bad_expect",) if verb in ("renew", "release", "transfer") else ())
        usage += (("bad_ttl",) if verb in ("claim", "renew") else ())
        usage += (("bad_branch", "bad_glob") if verb == "claim" else ())
        for case in ("valid", "oversized", "invalid_arguments", "not_repository", "git_io") + usage + LEASE_REFUSALS.get(verb, ()):
            for mode in ("text", "json"):
                rows.append(("lease", verb, case, mode))
    for case in MODEL_CASES:
        rows.append(("model", "model", case, "json"))
    for case in ("invalid_log_path", "unsafe_decision_path", "unsafe_decision_directory", "anchored_io_unavailable"):
        rows.append(("core-model", "read_decisions", case, "exception"))
    for verb, cases in MESSAGE_CASES.items():
        for case in cases:
            rows.append(("msg", verb, case, "json"))
    for verb in PROFILE_PATHS:
        cases = ("valid", "oversized") + (() if verb == "config presets" else ("invalid_profile",))
        cases += {"doctor": ("missing_cli",), "config init": ("exists", "invalid_preset"),
                  "hosts check": ("unknown_host", "unknown_kind")}.get(verb, ())
        for case in cases:
            for mode in ("text", "json"):
                rows.append(("profile", verb, case, mode))
    for value in ("model", "msg"):
        for case in ("valid", "malformed", "oversized", "workspace"):
            rows.append(("mixed", value, case, "json"))
    return rows


class _FrozenMessageClock:
    @staticmethod
    def now(zone=None):
        return datetime.fromtimestamp(100, timezone.utc)


def test_operation_matrix_covers_refusal_siblings():
    required = set()
    for family, modes in (("cli-queue", ("text", "json")), ("core-queue", ("dict",))):
        for verb in ("claim", "release", "done", "unclaim"):
            for case in ("item_done", "malformed_identifier", "malformed_revision"):
                required.update((family, verb, case, mode) for mode in modes)
        required.update((family, "list", "malformed_capability", mode) for mode in modes)
    for case in ("invalid_log_path", "unsafe_decision_path", "unsafe_decision_directory", "anchored_io_unavailable"):
        required.add(("model", "model", case, "json"))
        required.add(("core-model", "read_decisions", case, "exception"))
    for verb in ("renew", "gc"):
        required.update(("lease", verb, "ambient_git_environment", mode) for mode in ("text", "json"))
    assert required <= set(_operation_rows()), sorted(required - set(_operation_rows()))
    assert {"/".join(row) for row in required} <= OPERATION_GOLDENS.keys()


def _compat_git(root, *arguments):
    result = subprocess.run(["git", "-c", "user.name=Dev", "-c", "user.email=dev@example.com",
                             "-c", "commit.gpgsign=false", *arguments], cwd=root,
                            env={**os.environ, "GIT_AUTHOR_DATE": "2001-01-01T00:00:00Z",
                                 "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z"},
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@contextmanager
def _compat_lease_environment(root, case):
    previous = os.environ.get("GIT_DIR")
    if case == "ambient_git_environment":
        os.environ["GIT_DIR"] = str(root / ".git")
    try:
        yield
    finally:
        if case == "ambient_git_environment":
            if previous is None:
                os.environ.pop("GIT_DIR", None)
            else:
                os.environ["GIT_DIR"] = previous


def _compat_queue_setup(root, verb, case):
    value = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    added = team_queue.add(root, value, now=100, caller="owner")
    assert not added["refused"], added
    row = added["item"]
    if verb in ("release", "unclaim", "done") or (verb == "compact" and case == "valid") or case in (
            "already_claimed", "lane_busy", "capacity_full", "unclaim_recovery_required", "item_done",
            "queue_history_limit"):
        result = team_queue.claim(root, "ONE", expect=row["revision"], lane="writer", now=100,
                                  branch="lane/writer", caller="owner")
        assert not result["refused"], result
        row = result["item"]
    if case in ("item_done", "queue_history_limit") or (verb == "compact" and case == "valid"):
        result = team_queue.done(root, "ONE", expect=row["revision"], lane="writer", now=100, caller="owner")
        assert not result["refused"], result
        row = result["item"]
    if case == "item_done":
        compacted = team_queue.compact(root, now=100, caller="owner")
        assert compacted["removed_ids"] == ["ONE"] and compacted["exit_code"] == 0
        state = json.loads((root / ".aegis/state/team-queue.json").read_text(encoding="utf-8"))
        assert "ONE" not in state["items"] and state["completed"]["ONE"] is True
    arguments = {"identifier": "ONE", "expect": row["revision"], "lane": "writer"}
    if verb == "add":
        arguments = {"item": {**value, "id": "TWO"}}
    elif verb == "claim":
        arguments.update(capabilities=[], ttl_s=60, branch="lane/writer")
    elif verb == "unclaim":
        arguments.update(writer_stopped=True, reason="Waiting")
    elif verb in ("list", "audit", "compact"):
        arguments = {}
    return value, row, arguments


def _compat_queue_refusal(root, verb, case, value, row, arguments):
    path = root / ".aegis/state/team-queue.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    if case == "invalid_item":
        if verb == "add":
            arguments["item"] = {}
        else:
            arguments["reason"] = "bad\nreason"
    elif case in ("credential_like_text", "brief_outside_scope"):
        if verb == "unclaim":
            arguments["reason"] = "token=private-value"
        else:
            arguments["item"]["title" if case == "credential_like_text" else "brief_paths"] = (
                "token=private-value" if case == "credential_like_text" else ["docs/a.md"])
    elif case == "item_exists":
        arguments["item"] = value
    elif case == "item_missing":
        arguments["identifier"] = "NONE"
    elif case == "stale_revision":
        arguments["expect"] = "0" * 64
    elif case == "malformed_identifier":
        arguments["identifier"] = "bad/id"
    elif case == "malformed_revision":
        arguments["expect"] = "z" * 64
    elif case == "malformed_capability":
        arguments["capabilities"] = ["bad/label"]
    elif case in ("lane_busy", "capacity_full"):
        other = team_queue.add(root, {**value, "id": "TWO", "paths": ["docs/**"]}, now=100, caller="owner")
        arguments.update(identifier="TWO", expect=other["item"]["revision"],
                         lane="writer" if case == "lane_busy" else "other")
    elif case == "capability_mismatch":
        state["items"]["ONE"]["item"]["capabilities"] = ["required"]
    elif case == "blocked":
        state["items"]["ONE"]["item"]["hold"] = "Coordinator decision"
    elif case == "profile_unavailable":
        target = root / ".aegis/team/profile.json"
        target.parent.mkdir(exist_ok=True)
        target.write_text('{"version":1,"run_config":{"limits":{"writers_max":0}}}', encoding="utf-8")
    elif case == "not_claimed":
        state["items"]["ONE"].update(state="queued", lane=None, expires_at=None)
    elif case in ("lane_required", "lane_mismatch"):
        arguments["lane"] = None if case == "lane_required" else "other"
    elif case == "lease_expired":
        state["items"]["ONE"]["expires_at"] = 99
    elif case == "writer_not_stopped":
        arguments["writer_stopped"] = False
    elif case == "writer_live":
        team.claim(root, "writer", ["src/**"], now=100, owner="owner", branch="lane/writer")
    elif case == "unclaim_lease_refused":
        team.claim(root, "foreign", ["src/**"], now=100, owner="foreign", branch="lane/writer")
    elif case == "unclaim_event_unavailable":
        # A non-directory receipt-store component refuses independently of metrics.
        (root / ".aegis/state/unclaim-receipts").write_bytes(b"not a directory")
    elif case == "unclaim_recovery_required":
        state["unclaim"] = {"id": "ONE", "revision": row["revision"], "lane": row["lane"], "caller": "other",
                            "reason": "Waiting", "lease_oid": None, "to_revision": "ab" * 32}
    elif case == "queue_history_limit":
        state["completed"] = {"DONE" + str(i): True for i in range(team_queue.MAX_COMPLETED)}
    elif case == "queue_live_limit":
        state["items"] = {"ITEM" + str(i): {**state["items"]["ONE"], "item": {**value, "id": "ITEM" + str(i)}}
                          for i in range(team_queue.MAX_ITEMS)}
    if case in ("capability_mismatch", "blocked", "not_claimed", "lease_expired", "unclaim_recovery_required",
                "queue_history_limit", "queue_live_limit"):
        path.write_text(json.dumps(state), encoding="utf-8")
    if case == "invalid_queue_state":
        path.write_bytes(b"{")
    elif case == "queue_size_limit":
        path.write_bytes(b" " * (team_queue.MAX_BYTES + 1))
    elif case == "queue_io_unavailable":
        path.unlink()
        path.mkdir()
    return arguments


def _compat_queue_argv(verb, arguments):
    argv = ["team", "queue", verb]
    if verb == "add":
        return argv + ["--item", json.dumps(arguments["item"])]
    if verb in ("claim", "release", "unclaim", "done"):
        argv += [arguments["identifier"], "--expect", arguments["expect"]]
        if arguments["lane"] is not None:
            argv += ["--lane", arguments["lane"]]
    if verb == "claim":
        argv += ["--ttl", str(arguments["ttl_s"]), "--branch", arguments["branch"]]
        for capability in arguments["capabilities"]:
            argv += ["--capability", capability]
    elif verb == "unclaim":
        argv += ["--reason", arguments["reason"]]
        if arguments["writer_stopped"]:
            argv.append("--writer-stopped")
    elif verb == "list":
        for capability in arguments.get("capabilities", ()):
            argv += ["--capability", capability]
    return argv


def _compat_lease_setup(root, verb, case):
    oid = "0" * 40
    lane = "writer"
    if verb != "claim" or case in ("taken", "unreadable", "legacy_paths"):
        expired = case in ("expired", "overlap") or (verb == "gc" and case == "valid")
        change = team.claim(root, lane, ["src/**"], owner="owner", branch="lane/writer",
                            now=1 if expired else 100, ttl_s=10 if expired else 3600)
        oid = change.oid
    if case == "taken":
        pass
    elif case == "overlap":
        team.claim(root, "foreign", ["src/**"], owner="owner", now=100, branch="lane/writer")
    elif case == "absent":
        team.release(root, lane, oid, caller="owner")
    elif case == "stale":
        oid = "0" * 40
    elif case in ("unreadable", "legacy_paths"):
        if case == "unreadable":
            raw = b"{}"
        else:
            raw = json.loads(compatibility_git.read_blobs(root, [oid])[oid])
            raw["paths"] = ["src/bad name.py"]
            raw = json.dumps(raw).encode()
        bad = compatibility_git.write_blob(root, raw)
        compatibility_git.update_ref(root, team.lane_ref(lane), bad, oid)
        oid = bad
    elif case == "lease_branch_missing":
        _compat_git(root, "update-ref", "-d", "refs/heads/lane/writer")
    argv = ["team", verb]
    if verb == "claim":
        argv += [lane, "--paths", "src/**", "--owner", "owner", "--branch", "lane/writer"]
    elif verb in ("renew", "release", "transfer"):
        argv += [lane, "--expect", oid]
        if verb == "transfer":
            argv += ["--owner", "next-owner"]
    elif verb in ("status", "metrics"):
        argv += ["--base", "no-such-base" if case == "bad_base" else "main"]
    if case == "invalid_arguments":
        argv += ["--unknown=private-value"]
    elif case == "bad_lane":
        argv[2] = "bad/lane"
    elif case == "bad_expect":
        argv[argv.index("--expect") + 1] = "invalid"
    elif case == "bad_ttl":
        argv += ["--ttl", "0"]
    elif case == "bad_branch":
        argv[argv.index("--branch") + 1] = "bad branch"
    elif case == "bad_glob":
        argv[argv.index("--paths") + 1] = "../outside"
    return argv


def _compat_model_setup(root, case):
    bindings = json.loads((Path(__file__).resolve().parents[3] /
                           "tools/hierarchy_templates/model-bindings.json").read_text(encoding="utf-8"))
    for row in bindings["hosts"]:
        if row["host"] in ("codex-cli", "claude-code") and row["class"] == "coding":
            for intent, level in row["levels"].items():
                if level is not None:
                    row["admission"][intent] = "admitted"
    policy = {"team_id": "team-one", "manager_family": "second", "team_family": "first",
              "target_shares": {"first": 0.7, "second": 0.3}, "family_order": ["first", "second"],
              "flexible_tasks": ["T9", "T10", "T14"], "family_hosts": {"first": ["codex-cli"], "second": ["claude-code"]},
              "review_families": {"T4": {"primary": "second"}, "T5": {"primary": "first"},
                                  "T6": {"primary": "first", "whole": "second"},
                                  "T8": {"primary": "opposite", "second": "author"}}}
    if case in ("binding_unavailable", "unadmitted"):
        selected = next(row for row in bindings["hosts"] if row["host"] == "codex-cli" and row["class"] == "coding")
        if case == "binding_unavailable":
            for row in bindings["hosts"]:
                if row["host"] == "codex-cli":
                    row["host_status"] = "planned"
        else:
            selected["admission"]["standard"] = "unprobed"
    for name, value in (("bindings.json", bindings), ("policy.json", policy)):
        (root / name).write_text(json.dumps(value), encoding="utf-8")
    (root / "history.jsonl").write_text("", encoding="utf-8")
    if case in ("invalid_bindings", "invalid_policy", "invalid_history"):
        target = {"invalid_bindings": "bindings.json", "invalid_policy": "policy.json", "invalid_history": "history.jsonl"}[case]
        (root / target).write_text("{", encoding="utf-8")
    elif case == "missing_bindings":
        (root / "bindings.json").unlink()
    options = {"bindings": "bindings.json", "policy": "policy.json", "history": "history.jsonl",
               "task-kind": "T2", "role-kind": "implementer", "subject": "lane", "intent": "standard"}
    changes = {"unknown_task_kind": ("task-kind", "UNKNOWN"), "unknown_role_kind": ("role-kind", "UNKNOWN"),
               "task_role_mismatch": ("role-kind", "reviewer"), "invalid_subject": ("subject", "bad subject"),
               "unknown_intent": ("intent", "unknown"), "invalid_author_family": ("author-family", "unknown"),
               "invalid_lane_family": ("lane-family", "unknown"), "invalid_review_stage": ("review-stage", "second"),
               "model_output_needs_redaction": ("subject", "token=private-value")}
    changes.update(intent_outside_role_band=("intent", "ultra"), lane_family_mismatch=("lane-family", "unknown"),
                   unsafe_path=("history", "../history"), oversized_arguments=("subject", "x" * 262145))
    if case in changes:
        key, value = changes[case]
        options[key] = value
    if case == "invalid_lane_family":
        options.update({"task-kind": "T1", "role-kind": "orchestrator"})
    if case == "invalid_log_path":
        options["history"] = "history.lock"
        (root / "history.lock").write_text("", encoding="utf-8")
    elif case == "unsafe_decision_path":
        (root / "history.jsonl").unlink()
        (root / "history.jsonl").mkdir()
    elif case == "unsafe_decision_directory":
        directory = root / "unsafe"
        directory.mkdir()
        directory.chmod(0o777)
        (directory / "history.jsonl").write_text("", encoding="utf-8")
        options["history"] = "unsafe/history.jsonl"
    argv = ["team", "model", "--host-kind", "codex-cli", "--host-kind", "claude-code"]
    for key, value in options.items():
        argv += ["--" + key, value]
    if case in ("record", "model_lock_timeout"):
        argv += ["--record"]
    if case == "invalid_arguments":
        argv += ["--unknown=private-value"]
    return argv


def _compat_message_setup(root, verb, case):
    directory = root / "messages"
    directory.mkdir(mode=0o700)
    value = {"fields": {}, "body": "Hello", "refs": {}}
    if case == "missing_ref" and verb == "write":
        value["refs"] = {"child": "a" * 64}
    if case == "invalid_fields":
        value["fields"] = {"unexpected": 1}
    source = root / "input.json"
    source.write_text(json.dumps(value), encoding="utf-8")
    record = message_codec.compose("text", json.dumps({"fields": {}, "body": "Hello", "refs": {}}).encode(),
                                  {"from": "cli", "host": "cli", "session": "", "created_at": "1970-01-01T00:01:40Z"})
    with closing(message_codec.Store(directory)) as instance:
        rid = instance.write(record)
    if case == "invalid_json":
        source.write_text("{", encoding="utf-8")
    elif case == "large_input":
        source.write_bytes(b" " * (message_codec.MAX_BYTES + 1))
    elif case == "missing_input":
        source.unlink()
    elif case == "unsafe_store":
        directory.chmod(0o777)
    elif case == "hash":
        (directory / rid[:2] / (rid + ".json")).write_bytes(b"{}")
    if verb == "write":
        argv = ["msg", "--store", str(directory), "write", "--kind", "text", "--in", str(source)]
    else:
        reference = "a" * 64 if case == "missing_ref" else "bad" if case == "invalid_ref" else rid
        argv = ["msg", "--store", str(directory), verb, reference]
    if case in ("selector", "span", "expand", "limit", "format"):
        argv += {"selector": ["--fields", "bad["], "span": ["--spans", "999"],
                 "expand": ["--expand", "missing"], "limit": ["--max-chars", "1"],
                 "format": ["--format", "unknown"]}[case]
    return argv, rid


def _compat_profile_setup(root, verb, case):
    argv = ["team", *verb.split()]
    if verb == "config init":
        argv += ["--preset", "solo", "--host", "codex-cli"]
    elif verb == "hosts check":
        argv += ["primary", "writer"]
        if case == "unknown_host":
            argv[-2] = "missing"
        elif case == "unknown_kind":
            argv[-1] = "bad-kind"
    if case == "exists":
        team_profile.initialize(root, "solo", host="codex-cli")
    elif case == "invalid_preset":
        argv[argv.index("--preset") + 1] = "missing"
    if case == "invalid_profile":
        target = root / ".aegis/team/profile.json"
        target.parent.mkdir(exist_ok=True)
        target.write_text("{", encoding="utf-8")
    return argv


def _compat_observation(key, observation, root):
    import re

    code, stdout, stderr = observation
    stderr = _canonical_cli_os_error(stderr)
    oversized = str(Path.cwd() / ("x" * 32769))
    stderr = stderr.replace(oversized, "CWD/" + "x" * 32769)
    streams = [re.sub(r'"checked_at": "[^"]+"', '"checked_at": "CLOCK"',
                      stream.replace(str(root.parent / "plain"), "PLAIN").replace(str(root), "ROOT")
                      .replace("optional arguments:\n", "options:\n"))
               for stream in (stdout, stderr)]
    actual = [code, *streams]
    digest = hashlib.sha256(json.dumps(actual, ensure_ascii=True).encode()).hexdigest()
    assert digest == OPERATION_GOLDENS[key], (key, digest)
    return actual


@pytest.mark.parametrize("family,verb,case,mode", _operation_rows(),
                         ids=lambda value: value.replace(" ", "-"))
def test_public_operation_byte_goldens(_operation_workspace, capsys, monkeypatch, family, verb, case, mode):
    from itertools import count

    monkeypatch.setenv("COLUMNS", "80")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("PYTHON_COLORS", "0")
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    root = workspace = _operation_workspace
    revisions = count(1)
    randomness = SimpleNamespace(token_hex=lambda size: format(next(revisions), "0" + str(size * 2) + "x"))
    monkeypatch.setattr(team_queue, "secrets", randomness)
    monkeypatch.setattr(team_claims, "secrets", randomness)
    monkeypatch.setattr(team, "secrets", randomness)
    monkeypatch.setattr(team_queue, "time", SimpleNamespace(time=lambda: 100))
    monkeypatch.setattr(cli_team, "time", SimpleNamespace(time=lambda: 100))
    monkeypatch.setattr(team, "time", SimpleNamespace(time=lambda: 100))
    monkeypatch.setattr(team, "default_owner", lambda: "owner")
    monkeypatch.setattr(events, "utc_stamp", lambda: "1970-01-01T00:01:40Z")
    monkeypatch.setattr(cli_msg, "datetime", _FrozenMessageClock)
    monkeypatch.setattr(team_profile, "pathlookup", SimpleNamespace(which=lambda *args, **options: "/host/cli"))
    (root / ".aegis/team.json").write_text(json.dumps({"v": 1, "lanes": {"writer": ["src/**"], "other": ["docs/**"]}}))
    expected_reason = None
    if family.endswith("queue"):
        value, row, arguments = _compat_queue_setup(root, verb, case)
        arguments = _compat_queue_refusal(root, verb, case, value, row, arguments)
        if case in QUEUE_REFUSALS.get(verb, ()) or case in (
                "invalid_queue_state", "queue_size_limit", "unsupported_platform", "queue_io_unavailable",
                "queue_lock_timeout", "unclaim_recovery_required"):
            expected_reason = case
        if case == "unsupported_platform":
            monkeypatch.setattr(team_queue, "descriptor_supported", lambda: False)
        elif case == "writer_live":
            monkeypatch.setattr(binding, "judge", lambda home, found, summary:
                                {"state": "unknown", "reason": "writer_bound", "leases": summary})
        elif case == "queue_lock_timeout":
            def refuse_lock(*args, **options):
                raise storage.LockTimeoutError("boundary unavailable")
            monkeypatch.setattr(team_queue, "locked", refuse_lock)
        if case == "invalid_arguments":
            if family == "core-queue":
                arguments["now"] = -1
            expected_reason = "invalid_arguments"
        elif case in ("malformed_identifier", "malformed_revision", "malformed_capability"):
            expected_reason = "invalid_arguments"
        argv = _compat_queue_argv(verb, arguments) if family == "cli-queue" else []
        if case == "invalid_arguments" and family == "cli-queue":
            argv += ["--unknown=private-value"]
    elif family == "lease":
        argv = _compat_lease_setup(root, verb, case)
        if case == "not_repository":
            root = root.parent / "plain"
            (root / ".aegis").mkdir(parents=True)
        elif case == "git_io":
            def unavailable(*args, **options):
                raise compatibility_git.GitError("git boundary unavailable")
            monkeypatch.setattr(compatibility_git, "run", unavailable)
    elif family in ("model", "core-model"):
        argv = _compat_model_setup(root, case)
        if case == "anchored_io_unavailable":
            monkeypatch.setattr(model_select, "_DIR_FD_SUPPORTED", False)
        elif case == "model_workspace_unavailable":
            root = root.parent / "plain"
            root.mkdir()
        elif case in ("model_lock_timeout", "model_io_unavailable"):
            def unavailable(*args, **options):
                if case == "model_lock_timeout":
                    raise storage.LockTimeoutError("boundary unavailable")
                raise OSError("boundary unavailable")
            if case == "model_lock_timeout":
                monkeypatch.setattr(model_select, "file_lock", unavailable)
            else:
                monkeypatch.setattr(model_select, "read_decisions", unavailable)
    elif family == "msg":
        argv, rid = _compat_message_setup(root, verb, case)
        if case == "unsupported":
            monkeypatch.setattr(cli_msg, "_anchored_operations_supported", lambda: False)
        elif case == "io":
            def unavailable(*args, **options):
                raise OSError("boundary unavailable")
            monkeypatch.setattr(cli_msg, "_open_store", unavailable)
    elif family == "profile":
        argv = _compat_profile_setup(root, verb, case)
        if case == "missing_cli":
            monkeypatch.setattr(team_profile, "pathlookup", SimpleNamespace(which=lambda *args, **options: None))
    else:
        argv = ["team", "queue", "list", "--capability", verb]
        if case == "malformed":
            argv += ["--unknown=private-value"]
        elif case == "workspace":
            root = root.parent / "missing"
    capsys.readouterr()
    if family == "core-model":
        history = root / argv[argv.index("--history") + 1]
        with pytest.raises(model_select.ModelSelectionError, match="^" + case + "$") as refused:
            with closing(model_select.read_decisions(history)) as reader:
                list(reader)
        # This core surface raises an exception; it has no process exit code.
        code, stderr = None, ""
        stdout = json.dumps({"exception": type(refused.value).__name__, "message": str(refused.value)}, indent=2) + "\n"
    elif family == "core-queue":
        target = "x" * 32769 if case == "oversized" else root
        result = getattr(team_queue, verb)(target, **arguments)
        code, stdout, stderr = result["exit_code"], json.dumps(result, indent=2) + "\n", ""
    else:
        if case == "oversized":
            root_argument = "x" * 32769
        else:
            root_argument = str(root)
        with _compat_lease_environment(root, case):
            try:
                code = main(["--workspace", root_argument, *argv, *(["--json"] if mode == "json" else [])])
            except SystemExit as error:
                code = error.code
        captured = capsys.readouterr()
        stdout, stderr = captured.out, captured.err
    if expected_reason:
        assert json.loads(stdout)["reason"] == expected_reason, (family, verb, case, stdout, stderr)
        if expected_reason in ("unclaim_event_unavailable", "unclaim_recovery_required"):
            remedy = json.loads(stdout)["next_action"]
            assert ".aegis/state/unclaim-receipts" in remedy
            assert "events" not in remedy and "16 MiB" not in remedy
        if case in ("malformed_identifier", "malformed_revision", "malformed_capability"):
            assert json.loads(stdout)["schema"] == "aegis.team.queue." + verb + "/v1"
    if family == "model" and case in (
            "invalid_log_path", "unsafe_decision_path", "unsafe_decision_directory", "anchored_io_unavailable"):
        assert code == 2 and json.loads(stdout) == {"error": case}
    if family == "lease" and case == "ambient_git_environment":
        assert code == 1
        if mode == "json":
            assert json.loads(stdout)["reason"] == case
        else:
            assert stderr.startswith(case + "\n")
    if case in ("valid", "record"):
        assert code == 0, (family, verb, stdout, stderr)
    else:
        assert code != 0, (family, verb, case, stdout, stderr)
    key = "/".join((family, verb, case, mode))
    _compat_observation(key, [code, stdout, stderr], workspace)


def _shell_command(text):
    quote = None
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
            continue
        if char == ";":
            return text[:index]
    return text


@pytest.mark.parametrize("workspace_name", ["plain", "work space qu'ote; literal"])
def test_cli_recovery_from_another_cwd_names_and_reaches_its_workspace(
        workspace, tmp_path, capsys, monkeypatch, workspace_name):
    """An explicit --workspace copied from another directory still acts on the issuer."""
    from aegis_core.workspace.binding import resolve_cli_root

    workspace = workspace.rename(tmp_path / workspace_name)
    os.environ.pop("AEGIS_WORKSPACE", None)
    other = tmp_path / "elsewhere"
    shutil.copytree(workspace, other)
    owner = team.default_owner()
    added = team_queue.add(workspace, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []},
                           now=100, caller=owner)
    claimed = team_queue.claim(workspace, "ONE", expect=added["item"]["revision"], lane="writer",
                               now=101, caller=owner, branch="lane/writer")
    assert not claimed["refused"], claimed
    # Queue claim does not create the git lease. A live lease makes the first
    # unclaim call _release_lease, which this test fails once.
    team.claim(workspace, "writer", ["src/**"], owner=owner)
    revision = claimed["item"]["revision"]
    original = team_claims._release_lease
    calls = {"n": 0}

    def fail_once(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("injected")
        return original(*args, **kwargs)

    monkeypatch.setattr(team_claims, "_release_lease", fail_once)
    previous = os.getcwd()
    os.chdir(other)
    try:
        code = main(["--workspace", str(workspace), "team", "queue", "unclaim", "ONE",
                     "--expect", revision, "--lane", "writer", "--writer-stopped", "--json"])
        refused = json.loads(capsys.readouterr().out)
        assert code == 1 and refused["reason"] == "unclaim_recovery_required"
        blocker = refused["blockers"][0]
        assert (blocker["caller"], blocker["revision"], blocker["reason_text"]) == (owner, revision, "")
        command = _shell_command(blocker["next_action"])
        argv = shlex.split(command)
        assert "--workspace" in argv, command
        token = argv[argv.index("--workspace") + 1]
        assert token == str(workspace)
        assert resolve_cli_root(token, other) == workspace.resolve()
        # The refusal sentence introduces the command. Replay from the program name.
        replay = argv[argv.index("aegis") + 1:]
        for verb, extra in (
            ("list", []),
            ("audit", []),
            ("release", ["ONE", "--expect", revision, "--lane", "writer"]),
        ):
            code = main(["--workspace", str(workspace), "team", "queue", verb, *extra, "--json"])
            payload = json.loads(capsys.readouterr().out)
            assert code == 1 and payload["reason"] == "unclaim_recovery_required"
            again = shlex.split(_shell_command(payload["blockers"][0]["next_action"]))
            assert again[again.index("--workspace") + 1] == str(workspace)
            assert (payload["blockers"][0]["caller"], payload["blockers"][0]["revision"],
                    payload["blockers"][0]["reason_text"]) == (owner, revision, "")
        code = main(replay + ["--json"])
        recovered = json.loads(capsys.readouterr().out)
        assert code == 0 and recovered["refused"] is False, recovered
        assert recovered["item"]["state"] == "queued"
        assert not (other / ".aegis" / "state" / "team-queue.json").exists()
        listed = team_queue.list(workspace, now=102)
        assert listed["refused"] is False and listed["items"][0]["state"] == "queued"
    finally:
        os.chdir(previous)


def _build_operation_repository_seed(base, environ):
    """Build the deterministic Git base using an explicit caller environment."""
    if not team_queue.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    if shutil.which("git") is None:
        pytest.skip("requires git")
    root = base / "workspace"
    (root / ".aegis" / "rules").mkdir(parents=True)
    (root / ".aegis" / "team.json").write_text(
        json.dumps({"v": 1, "lanes": {"writer": ["src/**"]}}), encoding="utf-8")
    home = base / "home"
    home.mkdir()
    environment = {**environ, "HOME": str(home), "USERPROFILE": str(home),
                   "XDG_CONFIG_HOME": str(home / ".config"),
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
                   "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_AUTHOR_DATE": "2001-01-01T00:00:00Z",
                   "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z"}
    subprocess.run(["git", "init", "-q", str(root)], check=True, env=environment)
    for arguments in (("symbolic-ref", "HEAD", "refs/heads/main"),
                      ("commit", "--allow-empty", "-qm", "base"),
                      ("update-ref", "refs/heads/lane/writer", "HEAD")):
        result = subprocess.run(
            ["git", "-c", "user.name=Dev", "-c", "user.email=dev@example.com",
             "-c", "commit.gpgsign=false", *arguments], cwd=root, env=environment,
            capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
    return root


@pytest.fixture(scope="session")
def _operation_repository_seed(tmp_path_factory):
    """Build the operation matrix's deterministic Git base once per worker."""
    return _build_operation_repository_seed(
        tmp_path_factory.mktemp("operation-repository-seed"), os.environ)


@pytest.fixture
def _operation_workspace(tmp_path, _operation_repository_seed):
    """Give each matrix case a private copy, including independent Git objects."""
    root = tmp_path / "workspace"
    shutil.copytree(_operation_repository_seed, root)
    home = tmp_path / "home"
    home.mkdir()
    # The same autouse environment restoration used by workspace applies here.
    os.environ.update({"HOME": str(home), "USERPROFILE": str(home)})
    return root


@pytest.mark.parametrize("configuration", ("home", "xdg", "global", "system"))
def test_operation_seed_ignores_user_templates(tmp_path, configuration):
    if os.name == "nt":
        pytest.skip("requires executable POSIX Git hooks")
    if not team_queue.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    if shutil.which("git") is None:
        pytest.skip("requires git")
    home = tmp_path / "developer-home"
    home.mkdir()
    xdg = tmp_path / "developer-config"
    (xdg / "git").mkdir(parents=True)
    template = tmp_path / "developer-template"
    (template / "hooks").mkdir(parents=True)
    for name in ("pre-commit", "commit-msg"):
        hook = template / "hooks" / name
        hook.write_text("#!/bin/sh\necho developer-template-hook-ran >&2\nexit 86\n",
                        encoding="utf-8")
        hook.chmod(0o755)
    config = {"home": home / ".gitconfig", "xdg": xdg / "git" / "config",
              "global": tmp_path / "global.gitconfig", "system": tmp_path / "system.gitconfig"}[configuration]
    config.write_text("[init]\n\ttemplateDir = " + json.dumps(template.as_posix()) + "\n", encoding="utf-8")
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    environment.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(xdg),
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
                       GIT_CONFIG_NOSYSTEM="1", PYTEST_ADDOPTS="")
    if configuration in ("home", "xdg"):
        environment.pop("GIT_CONFIG_GLOBAL")
    elif configuration == "global":
        environment["GIT_CONFIG_GLOBAL"] = str(config)
    else:
        environment["GIT_CONFIG_SYSTEM"] = str(config)
        environment.pop("GIT_CONFIG_NOSYSTEM")
    base = tmp_path / "seed"
    base.mkdir()
    seeds = [_build_operation_repository_seed(base, environment)]
    copies = [shutil.copytree(seeds[0], tmp_path / ("copy-" + str(index)))
              for index in range(2)]
    assert len(seeds) == 1 and len(copies) == 2
    for root in seeds + copies:
        for name in ("pre-commit", "commit-msg"):
            assert not (root / ".git" / "hooks" / name).exists()
        assert (root / ".git" / "refs" / "heads" / "main").read_text(encoding="ascii") == (
            root / ".git" / "refs" / "heads" / "lane" / "writer").read_text(encoding="ascii")
        assert (root / ".git" / "refs" / "heads" / "main").read_bytes() == (
            seeds[0] / ".git" / "refs" / "heads" / "main").read_bytes()


@pytest.mark.parametrize("command", ("init", "symbolic-ref", "commit", "update-ref"))
def test_operation_seed_git_failure_is_error_and_retry_succeeds(tmp_path, monkeypatch, command):
    if not team_queue.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    if shutil.which("git") is None:
        pytest.skip("requires git")
    processes = subprocess
    failed = []

    def run(arguments, **options):
        if command in arguments and not failed:
            failed.append(command)
            if options.get("check"):
                raise processes.CalledProcessError(86, arguments)
            return processes.CompletedProcess(arguments, 86, stderr="injected seed git failure")
        return processes.run(arguments, **options)

    monkeypatch.setattr("tests.unit.cli.test_cli_team_queue.subprocess", SimpleNamespace(run=run))
    base = tmp_path / "failed"
    base.mkdir()
    error = processes.CalledProcessError if command == "init" else AssertionError
    with pytest.raises(error) as caught:
        _build_operation_repository_seed(base, os.environ)
    if command == "init":
        assert caught.value.returncode == 86
        assert caught.value.cmd[:2] == ["git", "init"]
    else:
        assert str(caught.value).splitlines()[0] == "injected seed git failure"
    assert failed == [command]
    retry = tmp_path / "retry"
    retry.mkdir()
    root = _build_operation_repository_seed(retry, os.environ)
    assert (root / ".git" / "refs" / "heads" / "main").read_bytes() == (
        root / ".git" / "refs" / "heads" / "lane" / "writer").read_bytes()


@pytest.mark.parametrize("boundary", ("descriptor", "git"))
def test_operation_seed_unsupported_boundary_skips(tmp_path, monkeypatch, boundary):
    monkeypatch.setattr("tests.unit.cli.test_cli_team_queue.team_queue", SimpleNamespace(
        descriptor_supported=lambda: boundary != "descriptor"))
    monkeypatch.setattr("tests.unit.cli.test_cli_team_queue.shutil", SimpleNamespace(which=lambda name: None))
    reason = ("requires descriptor-relative nofollow operations" if boundary == "descriptor"
              else "requires git")
    with pytest.raises(pytest.skip.Exception) as caught:
        _build_operation_repository_seed(tmp_path, os.environ)
    assert str(caught.value) == reason


def test_operation_seed_template_check_skips_on_windows(tmp_path, monkeypatch):
    monkeypatch.setattr("tests.unit.cli.test_cli_team_queue.os", SimpleNamespace(name="nt"))
    with pytest.raises(pytest.skip.Exception) as caught:
        test_operation_seed_ignores_user_templates(tmp_path, "home")
    assert str(caught.value) == "requires executable POSIX Git hooks"
