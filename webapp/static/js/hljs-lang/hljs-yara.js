/**
 * hljs-yara.js — highlight.js language definition for YARA rules.
 *
 * Ported from the Rulezet project (github.com/ngsoti/rulezet-core,
 * AGPL-3.0), so a rule looks the same in zsazsa's rule viewer as on Rulezet.
 * highlight.js ships no official grammar for it, so it is registered at
 * runtime with hljs.registerLanguage() by rulezet-code-modal.js, which loads
 * this file with a dynamic import() the first time a rule is shown.
 */
export default function yaraLanguage(hljs) {
    const KEYWORDS = {
        keyword:
            'rule private global import include meta strings condition ' +
            'all any of them for in at entrypoint filesize contains ' +
            'startswith endswith icontains istartswith iendswith matches ' +
            'wide ascii nocase fullword base64 base64wide xor and or not defined',
        literal: 'true false',
    }

    const HEX_STRING = {
        // { 4D 5A ?? ?? [4-8] E8 } — wildcard/jump bytes and nested comments
        className: 'string',
        begin: /\{/,
        end: /\}/,
        contains: [
            hljs.COMMENT('//', '$'),
            hljs.COMMENT('/\\*', '\\*/'),
        ],
        relevance: 0,
    }

    const IDENTIFIER = {
        // string/rule references: $a, $string1, #a, @a, !a, $
        className: 'variable',
        begin: /[$#@!]\w*/,
    }

    const RULE_TITLE = {
        className: 'title.function',
        begin: /(?<=\brule\s)[a-zA-Z_]\w*/,
        relevance: 0,
    }

    return {
        name: 'YARA',
        aliases: ['yar'],
        case_insensitive: false,
        keywords: KEYWORDS,
        contains: [
            hljs.COMMENT('//', '$'),
            hljs.COMMENT('/\\*', '\\*/'),
            hljs.QUOTE_STRING_MODE,
            HEX_STRING,
            IDENTIFIER,
            RULE_TITLE,
            hljs.C_NUMBER_MODE,
        ],
    }
}
