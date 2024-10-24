# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
# pylint: disable=invalid-name, line-too-long

'''Generate counters API for counter specifications in JSON files'''

# Generat header file
# Generate init function
# Generate clear function

import os
import json
from enum import Enum
from pydantic import BaseModel
import typer

app = typer.Typer()

def enum_element(prefix, name):
    '''Generate enum element name'''
    return prefix + name.upper().replace('-', '_')
# Counters data model
class EntryTypeEnum(str, Enum):
    '''Counter entry type'''
    SIMPLE = 'simple'
    COMBINED = 'combined'

    def __str__(self):
        return self.value

class UnitTypeEnum(str, Enum):
    '''Counter unit type'''
    PKTS = 'pkts'
    COMBINED = 'octets-and-pkts'
    SESSION = 'sessions'

class Counter(BaseModel):
    '''Combined counter entry'''
    type: EntryTypeEnum
    description: str
    unit: UnitTypeEnum
    prefix: str
    symlink_prefix: str
    symlink: bool
    counter: list[str]

    def statseg_name(self, name):
        '''Generate statseg name'''
        return self.prefix + '/' + name + '-' + self.unit

    def statseg_symlinkname(self, name):
        '''Generate statseg symlink name'''
        return name + '-' + self.unit

    def gen_headers(self):
        '''Generate enum for a counter'''
        basename = self.prefix[1:].replace('/', '_')
        enum_name = basename + '_' + self.type +  '_counters_t'
        prefix = basename.upper() + '_COUNTER_'

        s = f'// {self.description}\n'
        s += 'typedef enum {\n'
        for name in self.counter:
            s += f'  {enum_element(prefix, name)},\n'
        s += f'  {prefix}N_{self.type.upper()}\n'
        s += f'}} {enum_name};\n'

        # Prototypes
        s += f'void {basename}_init_counters_{self.type}(vlib_{self.type}_counter_main_t *cm);\n'
        s += f'void {basename}_init_counters_{self.type}_per_instance(vlib_{self.type}_counter_main_t *, u32, char *, u32 **);\n'
        s += f'void {basename}_remove_counters_{self.type}_per_instance(u32 *);\n'
        return s

    def gen_init(self):
        '''Generate init function for a counter'''
        basename = self.prefix[1:].replace('/', '_')
        enum_name = basename + '_' + self.type +  '_counters_t'
        prefix = basename.upper() + '_COUNTER_'

        s = 'void\n'
        s += f'{basename}_init_counters_{self.type}(vlib_{self.type}_counter_main_t *cm)\n'
        s += '{\n'
        for name in self.counter:
            enum_name = enum_element(prefix, name)
            cnt_name = self.statseg_name(name)
            s += f'  cm[{enum_name}].stat_segment_name = "{cnt_name}";\n'
            s += f'  vlib_validate_{self.type}_counter(&cm[{enum_name}], 0);\n'
            s += f'  vlib_zero_{self.type}_counter(&cm[{enum_name}], 0);\n'
        s += '}\n'
        return s

    def gen_clear(self):
        '''Generate clear function for a counter'''
        basename = self.prefix[1:].replace('/', '_')
        enum_name = basename + '_' + self.type +  '_counters_t'
        prefix = basename.upper() + '_COUNTER_'

        s = 'void\n'
        s += f'{basename}_clear_counters_{self.type}(vlib_{self.type}_counter_main_t *cm)\n'
        s += '{\n'
        for name in self.counter:
            enum_name = enum_element(prefix, name)
            s += f'  vlib_zero_{self.type}_counter(&cm[{enum_name}], 0);\n'
        s += '}\n'
        return s

    def gen_init_per_instance(self):
        '''Generate init function for a counter per instance'''
        basename = self.prefix[1:].replace('/', '_')
        enum_name = basename + '_' + self.type +  '_counters_t'
        prefix = basename.upper() + '_COUNTER_'

        s = 'void\n'
        s += f'{basename}_init_counters_{self.type}_per_instance(vlib_{self.type}_counter_main_t *cm, u32 index, char *symlink_name, u32 **entry_index)\n'
        s += '{\n'
        if self.symlink:
            s += '  u32 symlink_index;\n'
        for name in self.counter:
            enum_name = enum_element(prefix, name)
            s += f'  vlib_validate_{self.type}_counter(&cm[{enum_name}], index);\n'
            s += f'  vlib_zero_{self.type}_counter(&cm[{enum_name}], index);\n'
            if self.symlink:
                symlink_name = self.statseg_symlinkname(name)
                s += f'  symlink_index = vlib_stats_add_symlink(cm[{enum_name}].stats_entry_index, index, "{self.symlink_prefix}/%s/{symlink_name}", symlink_name);\n'
                s += '  vec_add1(*entry_index, symlink_index);\n'

        s += '}\n'

        if self.symlink:
            s += 'void\n'
            s += f'{basename}_remove_counters_{self.type}_per_instance(u32 *entry_index)\n'
            s += '{\n'
            for name in self.counter:
                if self.symlink:
                    s += f'  vlib_stats_remove_entry(entry_index[{enum_element(prefix, name)}]);\n'
            # s += '  vec_free(entry_index[index]);\n'
            s += '}\n'

        return s

# Entry = Annotated[Union[SimpleCounter, CombinedCounter], Field(discriminator="type")]

class CountersModel(BaseModel):
    '''Counters'''
    counters: list[Counter]

    def gen_headers(self, header_name):
        '''Generate headers'''
        s = '/* SPDX-License-Identifier: Apache-2.0 */\n'
        s += '/* Auto-generated do not change. */\n'
        s += f'#ifndef included_{header_name}_h\n'
        for counter in self.counters:
            s += counter.gen_headers()
        s += '#endif\n'
        return s

    def gen_c(self, includepath):
        '''Generate init functions'''
        s = '/* SPDX-License-Identifier: Apache-2.0 */\n'
        s += '/* Auto-generated do not change. */\n'
        s += '#include <vlib/vlib.h>\n'
        s += '#include <vlib/stats/stats.h>\n'
        s += f'#include <{includepath}>\n'
        for counter in self.counters:
            s += counter.gen_init()
            s += counter.gen_init_per_instance()
            s += counter.gen_clear()
        return s

class Counters:
    '''Counters'''
    def __init__(self, counters, filename):
        self.counters = CountersModel(counters=counters)
        self.module = os.path.splitext(os.path.basename(filename))[0]
        self.includepath = f'{filename}.h'

    def gen_headers(self):
        '''Generate headers'''
        return self.counters.gen_headers(self.module)

    def gen_c(self):
        '''Generate init functions'''
        return self.counters.gen_c(self.includepath)

@app.command()
def main(jsonfile: typer.FileText, relpath: str, header: bool = False):
    '''Reads counter definitions from a JSON file and generates .c/.h counter definitions for the VPP stats segment'''
    data = json.load(jsonfile)
    c = Counters(counters=data, filename=relpath)
    if header:
        s = c.gen_headers()
    else:
        s = c.gen_c()
    print(s)

