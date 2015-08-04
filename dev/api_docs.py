# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import ast, _ast
import textwrap

import CommonMark


cur_dir = os.path.dirname(__file__)
project_dir = os.path.abspath(os.path.join(cur_dir, '..'))
docs_dir = os.path.join(project_dir, 'docs')
module_name = 'certbuilder'

md_source_map = {
    'docs/api.md': 'certbuilder/__init__.py'
}


def _get_func_info(docstring, def_lineno, code_lines, prefix):
    definition = code_lines[def_lineno - 1]
    definition = definition.strip().rstrip(':')

    description = ''
    found_colon = False

    params = ''

    for line in docstring.splitlines():
        if line and line[0] == ':':
            found_colon = True
        if not found_colon:
            if description:
                description += '\n'
            description += line
        else:
            if params:
                params += '\n'
            params += line

    description = description.strip()
    description_md = ''
    if description:
        description_md = "%s%s" % (prefix, description.replace("\n", "\n" + prefix))

    params = params.strip()
    if params:
        definition += (':\n%s    """\n%s    ' % (prefix, prefix)) + params.replace('\n', '\n%s    ' % prefix) + ('\n%s    """' % prefix)

    return (definition, description_md)


def _find_sections(md_ast, sections, last, last_class, total_lines=None):

    for child in md_ast.children:
        if child.t == 'ATXHeader':

            if child.level in {3, 5} and len(child.inline_content) == 2:
                first = child.inline_content[0]
                second = child.inline_content[1]
                if first.t != 'Code':
                    continue
                if second.t != 'Str':
                    continue
                type_name = second.c.strip()
                identifier = first.c.strip().replace('()', '').lstrip('.')

                if last:
                    sections[(last['type_name'], last['identifier'])] = (last['start_line'], child.start_line - 1)
                    last.clear()

                if type_name == 'function':
                    if child.level != 3:
                        continue

                if type_name == 'class':
                    if child.level != 3:
                        continue
                    last_class.append(identifier)

                if type_name in {'method', 'attribute'}:
                    if child.level != 5:
                        continue
                    identifier = last_class[-1] + '.' + identifier

                last.update({
                    'type_name': type_name,
                    'identifier': identifier,
                    'start_line': child.start_line,
                })

        elif child.t == 'BlockQuote':
            find_sections(child, sections, last, last_class)

    if last:
        sections[(last['type_name'], last['identifier'])] = (last['start_line'], total_lines)

find_sections = _find_sections


def run():
    print('Updating API docs...')

    md_files = []
    for root, _, filenames in os.walk(docs_dir):
        for filename in filenames:
            if not filename.endswith('.md'):
                continue
            md_files.append(os.path.join(root, filename))

    parser = CommonMark.DocParser()

    for md_file in md_files:
        md_file_relative = md_file[len(project_dir) + 1:]
        if md_file_relative in md_source_map:
            py_file = md_source_map[md_file_relative]
            py_path = os.path.join(project_dir, py_file)
        else:
            py_file = os.path.basename(md_file).replace('.md', '.py')
            py_path = os.path.join(project_dir, module_name, py_file)

        if not os.path.exists(py_path):
            continue

        with open(md_file, 'rb') as f:
            markdown = f.read().decode('utf-8')

        original_markdown = markdown
        md_lines = list(markdown.splitlines())
        md_ast = parser.parse(markdown)

        last_class = []
        last = {}
        sections = {}
        find_sections(md_ast, sections, last, last_class, markdown.count("\n") + 1)

        with open(os.path.join(py_path), 'rb') as f:
            code = f.read().decode('utf-8')
            module_ast = ast.parse(code, filename=py_file)
            code_lines = list(code.splitlines())

        added_lines = 0

        def _replace_md(key, sections, md_chunk, md_lines, added_lines):
            start, end = sections[key]
            start -= 1
            start += added_lines
            end += added_lines
            new_lines = md_chunk.split('\n')
            added_lines += len(new_lines) - (end - start)
            md_lines[start:end] = new_lines
            return added_lines

        for node in ast.iter_child_nodes(module_ast):
            if isinstance(node, _ast.FunctionDef):
                key = ('function', node.name)
                if key not in sections:
                    continue

                docstring = ast.get_docstring(node)
                def_lineno = node.lineno + len(node.decorator_list)

                definition, description_md = _get_func_info(docstring, def_lineno, code_lines, '> ')

                md_chunk = textwrap.dedent("""
                    ### `%s()` function

                    > ```python
                    > %s
                    > ```
                    >
                    %s
                """).strip() % (
                    node.name,
                    definition,
                    description_md
                )

                added_lines = _replace_md(key, sections, md_chunk, md_lines, added_lines)

            elif isinstance(node, _ast.ClassDef):
                if ('class', node.name) not in sections:
                    continue

                for subnode in node.body:
                    if isinstance(subnode, _ast.FunctionDef):
                        node_id = node.name + '.' + subnode.name

                        method_key = ('method', node_id)
                        is_method = method_key in sections

                        attribute_key = ('attribute', node_id)
                        is_attribute = attribute_key in sections

                        is_constructor = subnode.name == '__init__'

                        if not is_constructor and not is_attribute and not is_method:
                            continue

                        docstring = ast.get_docstring(subnode)
                        def_lineno = subnode.lineno + len(subnode.decorator_list)

                        if not docstring:
                            continue

                        if is_method or is_constructor:
                            definition, description_md = _get_func_info(docstring, def_lineno, code_lines, '> > ')

                            if is_constructor:
                                key = ('class', node.name)

                                md_chunk = textwrap.dedent("""
                                    ### `%s()` class

                                    > ##### constructor
                                    >
                                    > > ```python
                                    > > %s
                                    > > ```
                                    > >
                                    %s
                                """).strip() % (
                                    node.name,
                                    definition,
                                    description_md
                                )

                            else:
                                key = method_key

                                md_chunk = textwrap.dedent("""
                                    >
                                    > ##### `.%s()` method
                                    >
                                    > > ```python
                                    > > %s
                                    > > ```
                                    > >
                                    %s
                                """).strip() % (
                                    subnode.name,
                                    definition,
                                    description_md
                                )

                        else:
                            key = attribute_key

                            description = textwrap.dedent(docstring).strip()
                            description_md = "> > %s" % (description.replace("\n", "\n> > "))

                            md_chunk = textwrap.dedent("""
                                >
                                > ##### `.%s` attribute
                                >
                                %s
                            """).strip() % (
                                subnode.name,
                                description_md
                            )

                        added_lines = _replace_md(key, sections, md_chunk, md_lines, added_lines)

        markdown = '\n'.join(md_lines).strip() + '\n'

        if original_markdown != markdown:
            with open(md_file, 'wb') as f:
                f.write(markdown.encode('utf-8'))
