from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule, SigmaRuleTag
from sigma.correlations import SigmaCorrelationRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import SigmaCompareExpression
from sigma.data.mitre_attack import mitre_attack_tactics, mitre_attack_techniques
import sigma
import re
import json
from typing import ClassVar, Dict, Tuple, Pattern, List, Iterable, Optional


class KustoBackend(TextQueryBackend):
    """Kusto backend."""

    # TODO: change the token definitions according to the syntax. Delete these not supported by your backend.
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name: ClassVar[str] = "Kusto backend"
    formats: Dict[str, str] = {
        "default": "Plain Kusto queries",
    }
    requires_pipeline: bool = True

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[str] = (
        "({expr})"  # Expression for precedence override grouping as format string with {expr} placeholder
    )

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"
    eq_token: ClassVar[str] = (
        " =~ "  # Token inserted between field and value (without separator)
    )

    # String output
    ## Fields
    ### Quoting
    field_quote: ClassVar[str] = (
        "'"  # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    )
    field_quote_pattern: ClassVar[Pattern] = re.compile(
        "^\\w+$"
    )  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation: ClassVar[bool] = (
        True  # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).
    )

    ### Escaping
    field_escape: ClassVar[str] = (
        ""  # Character to escape particular parts defined in field_escape_pattern.
    )
    field_escape_quote: ClassVar[bool] = (
        True  # Escape quote string defined in field_quote
    )
    field_escape_pattern: ClassVar[Pattern] = re.compile(
        "\\s"
    )  # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote: ClassVar[str] = (
        '"'  # string quoting character (added as escaping character)
    )
    escape_char: ClassVar[str] = (
        "\\"  # Escaping character for special characrers inside string
    )
    wildcard_multi: ClassVar[str] = "*"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "*"  # Character used as single-character wildcard
    add_escaped: ClassVar[str] = (
        "\\"  # Characters quoted in addition to wildcards and string quote
    )
    filter_chars: ClassVar[str] = ""  # Characters filtered
    bool_values: ClassVar[Dict[bool, str]] = (
        {  # Values to which boolean values are mapped.
            True: "true",
            False: "false",
        }
    )

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[str] = "{field} startswith {value}"
    endswith_expression: ClassVar[str] = "{field} endswith {value}"
    contains_expression: ClassVar[str] = "{field} contains {value}"
    wildcard_match_expression: ClassVar[str] = (
        None  # Special expression if wildcards can't be matched with the eq_token operator
    )

    # Regular expressions
    re_expression: ClassVar[str] = (
        '{field} matches regex "{regex}"'  # Regular expression query as format string with placeholders {field} and {regex}
    )
    re_escape_char: ClassVar[str] = (
        "\\"  # Character used for escaping in regular expressions
    )
    re_escape: ClassVar[Tuple[str]] = ()  # List of strings that are escaped
    re_escape_escape_char: bool = True  # If True, the escape character is also escaped

    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.

    # cidr expressions
    cidr_wildcard: ClassVar[str] = "*"  # Character used as single wildcard
    cidr_expression: ClassVar[str] = (
        'ipv4_is_in_range({field}, "{value}")'  # CIDR expression query as format string with placeholders {field} = {value}
    )
    cidr_in_list_expression: ClassVar[str] = (
        'ipv4_is_in_any_range({field}, "{value}")'  # CIDR expression query as format string with placeholders {field} = in({list})
    )

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = (
        "{field} {operator} {value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    )
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Expression for comparing two event fields
    field_equals_field_expression: ClassVar[str] = (
        "{field1}=={field2}"  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    )
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (
        True,
        True,
    )  # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    field_null_expression: ClassVar[str] = (
        "isnull({field})"  # Expression for field has null value as format string with {field} placeholder for field name
    )

    # Field existence condition expressions.
    field_exists_expression: ClassVar[str] = (
        "{field} is null"  # Expression for field existence as format string with {field} placeholder for field name
    )
    field_not_exists_expression: ClassVar[str] = (
        "{field} is not null"  # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.
    )

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = True  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = True  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = (
        True  # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    )
    field_in_list_expression: ClassVar[str] = (
        "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    )
    or_in_operator: ClassVar[str] = (
        "in~"  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    )
    and_in_operator: ClassVar[str] = (
        "has_all"  # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    )
    list_separator: ClassVar[str] = ", "  # List element separator

    # Value not bound to a field
    unbound_value_str_expression: ClassVar[str] = (
        "{value}"  # Expression for string value not bound to a field as format string with placeholder {value}
    )
    unbound_value_num_expression: ClassVar[str] = (
        "{value}"  # Expression for number value not bound to a field as format string with placeholder {value}
    )
    unbound_value_re_expression: ClassVar[str] = (
        "_=~{value}"  # Expression for regular expression not bound to a field as format string with placeholder {value}
    )

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[str] = (
        "\n| "  # String used as separator between main query and deferred parts
    )
    deferred_separator: ClassVar[str] = (
        "\n| "  # String used to join multiple deferred query parts
    )
    deferred_only_query: ClassVar[str] = (
        "*"  # String used as query if final query only contains deferred expression
    )

    # We use =~ for eq_token so everything is case insensitive. But this cannot be used with ints/numbers in queries
    # So we can define a new token to use for SigmaNumeric types and override convert_condition_field_eq_val_num
    # to use it
    num_eq_token: ClassVar[str] = " == "

    # Correlations
    correlation_methods: ClassVar[Dict[str, str]] = {
        "stats": "Correlation with stats command",
    }
    default_correlation_method: ClassVar[str] = "stats"
    default_correlation_query: ClassVar[str] = {
        "stats": "{search}\n{aggregate}\n{condition}"
    }
    temporal_correlation_query: ClassVar[str] = {
        "stats": "{search}\n{typing}\n{aggregate}\n{condition}"
    }

    correlation_search_single_rule_expression: ClassVar[str] = "{query}"
    correlation_search_multi_rule_expression: ClassVar[str] = (
        "from {sources} | where {queries}"
    )
    correlation_search_multi_rule_query_expression: ClassVar[str] = "({query})"
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = " or "

    typing_expression: ClassVar[str] = "| eval event_type=case({queries})"
    typing_rule_query_expression: ClassVar[str] = '{query}, "{ruleid}"'
    typing_rule_query_expression_joiner: ClassVar[str] = ", "

    # not yet supported for Kusto because all queries from correlated rules are combined into one query.
    # correlation_search_field_normalization_expression: ClassVar[str] = " | rename {field} as {alias}"
    # correlation_search_field_normalization_expression_joiner: ClassVar[str] = ""

    event_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "stats": "| eval timebucket=date_trunc({timespan}, @timestamp) | stats event_count=count(){groupby}"
    }
    value_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "stats": "| eval timebucket=date_trunc({timespan}, @timestamp) | stats value_count=count_distinct({field}){groupby}"
    }
    temporal_aggregation_expression: ClassVar[Dict[str, str]] = {
        "stats": "| eval timebucket=date_trunc({timespan}, @timestamp) | stats event_type_count=count_distinct(event_type){groupby}"
    }

    timespan_mapping: ClassVar[Dict[str, str]] = {
        "s": "seconds",
        "m": "minutes",
        "h": "hours",
        "d": "days",
        "w": "weeks",
        "M": "months",
        "y": "years",
    }
    referenced_rules_expression: ClassVar[Dict[str, str]] = {"stats": "{ruleid}"}
    referenced_rules_expression_joiner: ClassVar[Dict[str, str]] = {"stats": ","}

    groupby_expression_nofield: ClassVar = {"stats": " by timebucket"}
    groupby_expression: ClassVar[Dict[str, str]] = {"stats": " by timebucket{fields}"}
    groupby_field_expression: ClassVar[Dict[str, str]] = {"stats": ", {field}"}
    groupby_field_expression_joiner: ClassVar[Dict[str, str]] = {"stats": ""}

    event_count_condition_expression: ClassVar[Dict[str, str]] = {
        "stats": "| where event_count {op} {count}"
    }
    value_count_condition_expression: ClassVar[Dict[str, str]] = {
        "stats": "| where value_count {op} {count}"
    }
    temporal_condition_expression: ClassVar[Dict[str, str]] = {
        "stats": "| where event_type_count {op} {count}"
    }

    def __init__(
        self,
        processing_pipeline: Optional[
            "sigma.processing.pipeline.ProcessingPipeline"
        ] = None,
        collect_errors: bool = False,
        schedule_interval: int = 5,
        schedule_interval_unit: str = "m",
        **kwargs,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.schedule_interval = schedule_interval
        self.schedule_interval_unit = schedule_interval_unit
        self.severity_risk_mapping = {
            "INFORMATIONAL": 1,
            "LOW": 21,
            "MEDIUM": 47,
            "HIGH": 73,
            "CRITICAL": 99,
        }

    def convert_correlation_search(
        self,
        rule: SigmaCorrelationRule,
        **kwargs,
    ) -> str:
        sources = [
            state.processing_state.get("query_table", "*")
            for rule_reference in rule.rules
            for state in rule_reference.rule.get_conversion_states()
        ]

        # Deduplicate sources using via set
        sources = list(set(sources))

        if "*" in sources:
            return super().convert_correlation_search(rule, sources="*", **kwargs)
        else:
            return super().convert_correlation_search(
                rule, sources=",".join(sources), **kwargs
            )

    def convert_correlation_search_multi_rule_query_postprocess(
        self, query: str
    ) -> str:
        return query.split(" | where ")[1]

    def convert_correlation_typing_query_postprocess(self, query: str) -> str:
        return self.convert_correlation_search_multi_rule_query_postprocess(query)

    ### Correlation end ###

    def finalize_query_default(
        self, rule: SigmaRule, query: str, query_table: int, state: ConversionState
    ) -> str:
        return f"from {state.processing_state.get('query_table', '*')} | where {query}"
