# Copyright (c) 2016 Red Hat, Inc.
# Author: Stanislav Kontar, Red Hat Product Security
# License: LGPLv3+

"""
Implements class for CVS43 specification as defined at
https://www.first.org/cvss/v4.0/specification-document .

The library is compatible with both Python 2 and Python 3.
"""

from __future__ import unicode_literals

import copy
import math
from decimal import ROUND_CEILING
from decimal import Decimal as D

from .constants4 import (
    METRICS_ABBREVIATIONS,
    METRICS_ABBREVIATIONS_JSON,
    METRICS_MANDATORY,
    METRICS_VALUE_NAMES,
    METRICS_VALUES,
    MACRO_VECTOR_NAMES,
    MACRO_VECTOR_VALUE_NAMES,
    MAX_COMPOSED,
    MAX_SEVERITY,
    OrderedDict,
)
from .exceptions import (
    CVSS4Error,
    CVSS4MalformedError,
    CVSS4MandatoryError,
)


def round_up(value):
    """
    Round up is defined as the smallest number, specified to one decimal place, that is equal to
    or higher than its input. For example, Round up (4.02) is 4.1; and Round up (4.00) is 4.0.
    """
    return value.quantize(D("0.1"), rounding=ROUND_CEILING)


class CVSS4(object):
    """
    Class to hold CVSS4 vector, parsed values, and all scores.
    """

    def __init__(self, vector):
        """
        Args:
            vector (str): string specifying CVSS4 vector, fields may be out of order, fields which
                          are not mandatory may be missing
        """
        self.vector = vector
        self.minor_version = None
        self.metrics = {}
        self.original_metrics = None
        self.missing_metrics = []

        self.parse_vector()
        self.check_mandatory()
        self.add_missing_optional()

    def parse_vector(self):
        """
        Parses metrics from the CVSS4 vector.

        Raises:
            CVSS4MalformedError: if vector is not in expected format
        """
        if self.vector == "":
            raise CVSS4MalformedError("Malformed CVSS4 vector, vector is empty")

        if self.vector.endswith("/"):
            raise CVSS4MalformedError('Malformed CVSS4 vector, trailing "/"')

        # Handle 'CVSS:3.x' in the beginning of vector and split vector
        if self.vector.startswith("CVSS:4.0/"):
            self.minor_version = 0
        else:
            raise CVSS4MalformedError(
                'Malformed CVSS4 vector "{0}" is missing mandatory prefix '
                "or uses unsupported CVSS version".format(self.vector)
            )

        try:
            fields = self.vector.split("/")[1:]
        except IndexError:
            raise CVSS4MalformedError('Malformed CVSS4 vector "{0}"'.format(self.vector))

        # Parse fields
        for field in fields:
            if field == "":
                raise CVSS4MalformedError('Empty field in CVSS4 vector "{0}"'.format(self.vector))

            try:
                metric, value = field.split(":")
            except ValueError:
                raise CVSS4MalformedError('Malformed CVSS4 field "{0}"'.format(field))

            if metric in METRICS_ABBREVIATIONS:
                if value in METRICS_VALUE_NAMES[metric]:
                    if metric in self.metrics:
                        raise CVSS4MalformedError('Duplicate metric "{0}"'.format(metric))
                    self.metrics[metric] = value
                else:
                    raise CVSS4MalformedError(
                        'Unknown value "{0}" in field "{1}"'.format(value, field)
                    )
            else:
                raise CVSS4MalformedError(
                    'Unknown metric "{0}" in field "{1}"'.format(metric, field)
                )

    def check_mandatory(self):
        """
        Checks if mandatory fields are in CVSS4 vector.

        Raises:
            CVSS4MandatoryError: if mandatory metric is missing in the vector
        """
        missing = []
        for mandatory_metric in METRICS_MANDATORY:
            if mandatory_metric not in self.metrics:
                missing.append(mandatory_metric)
        if missing:
            raise CVSS4MandatoryError('Missing mandatory metrics "{0}"'.format(", ".join(missing)))

    def add_missing_optional(self):
        """
        Adds missing optional parameters, so they match the mandatory ones. Original metrics are
        also stored, as they may be used for printing back the minimal vector.
        """
        self.original_metrics = copy.copy(self.metrics)
        for abbreviation in ["MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"]:
            if abbreviation not in self.metrics or self.metrics[abbreviation] == "X":
                self.metrics[abbreviation] = self.metrics[abbreviation[1:]]

    def get_value_description(self, abbreviation):
        """
        Gets textual description of specific metric specified by its abbreviation.
        """
        string_value = self.metric(abbreviation)
        result = METRICS_VALUE_NAMES[abbreviation][string_value]
        return result

    def metric(self, metric):
        selected = self.metrics[metric]

        # If E=X it will default to the worst case i.e. E=A
        if metric == "E" and selected == "X":
            return "A"

        # If CR=X, IR=X or AR=X they will default to the worst case i.e. CR=H, IR=H and AR=H
        if metric == "CR" and selected == "X":
            return "H"

        # IR:X is the same as IR:H
        if metric == "IR" and selected == "X":
            return "H"

        # AR:X is the same as AR:H
        if metric == "AR" and selected == "X":
            return "H"

        # All other environmental metrics just overwrite base score values,
        # so if they’re not defined just use the base score value.
        if "M" + metric in self.metrics:
            modified_selected = self.metrics["M" + metric]
            if modified_selected != "X":
                return modified_selected

        return selected

    def _eq1(self):
        # EQ1: 0-AV:N and PR:N and UI:N
        #      1-(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
        #      2-AV:P or not(AV:N or PR:N or UI:N)

        if self.metric("AV") == "N" and self.metric("PR") == "N" and self.metric("UI") == "N":
            return 0
        elif (self.metric("AV") == "N" or self.metric("PR") == "N" or self.metric("UI") == "N") \
                and not (self.metric("AV") == "N" and self.metric("PR") == "N" and self.metric("UI") == "N") \
                and not (self.metric("AV") == "P"):
            return 1
        elif self.metric("AV") == "P" \
                or not (self.metric("AV") == "N" or self.metric("PR") == "N" or self.metric("UI") == "N"):
            return 2

        raise CVSS4Error("Invalid state for equation 1")

    def _eq2(self):
        # EQ2: 0-(AC:L and AT:N)
        #      1-(not(AC:L and AT:N))

        if self.metric("AC") == "L" and self.metric("AT") == "N":
            return 0
        elif not (self.metric("AC") == "L" and self.metric("AT") == "N"):
            return 1

        raise CVSS4Error("Invalid state for equation 2")

    def _eq3(self):
        # EQ3: 0-(VC:H and VI:H)
        #      1-(not(VC:H and VI:H) and (VC:H or VI:H or VA:H))
        #      2-not (VC:H or VI:H or VA:H)

        if self.metric("VC") == "H" and self.metric("VI") == "H":
            return 0
        elif not (self.metric("VC") == "H" and self.metric("VI") == "H") \
                and (self.metric("VC") == "H" or self.metric("VI") == "H" or self.metric("VA") == "H"):
            return 1
        elif not (self.metric("VC") == "H" or self.metric("VI") == "H" or self.metric("VA") == "H"):
            return 2

        raise CVSS4Error("Invalid state for equation 3")

    def _eq4(self):
        # EQ4: 0-(MSI:S or MSA:S)
        #      1-not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)
        #      2-not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)

        if self.metric("MSI") == "S" or self.metric("MSA") == "S":
            return 0
        elif not (self.metric("MSI") == "S" or self.metric("MSA") == "S") and \
                (self.metric("SC") == "H" or self.metric("SI") == "H" or self.metric("SA") == "H"):
            return 1
        elif not (self.metric("MSI") == "S" or self.metric("MSA") == "S") and \
                not ((self.metric("SC") == "H" or self.metric("SI") == "H" or self.metric("SA") == "H")):
            return 2

        raise CVSS4Error("Invalid state for equation 4")

    def _eq5(self):
        # EQ5: 0 - E:A
        #      1 - E: P
        #      2 - E: U

        if self.metric("E") == "A":
            return 0
        elif self.metric("E") == "P":
            return 1
        elif self.metric("E") == "U":
            return 2

        raise CVSS4Error("Invalid state for equation 5")

    def _eq6(self):
        # EQ6: 0-(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
        #      1-not[(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]

        if (self.metric("CR") == "H" and self.metric("VC") == "H") \
                or (self.metric("IR") == "H" and self.metric("VI") == "H") \
                or (self.metric("AR") == "H" and self.metric("VA") == "H"):
            return 0
        elif not ((self.metric("CR") == "H" and self.metric("VC") == "H")
                  or (self.metric("IR") == "H" and self.metric("VI") == "H")
                  or (self.metric("AR") == "H" and self.metric("VA") == "H")):
            return 1

        raise CVSS4Error("Invalid state for equation 6")

    def lookup(self, *vector):
        return METRICS_VALUES.get("".join(map(str, vector)), float('nan'))

    def macro_vector(self):
        """
        Builds the macro vector

        Returns:
            (str): six digit macro vector as a string
        """
        return self._eq1(), self._eq2(), self._eq3(), self._eq4(), self._eq5(), self._eq6()

    def _get_lower(self, index, *vector):
        return self.lookup(*[val + 1 if i + 1 == index else val for i, val in enumerate(vector)])

    def lower_scores(self, macro_vector):
        _, _, eq3, _, _, eq6 = macro_vector

        eq1_next_lower = self._get_lower(1, *macro_vector)
        eq2_next_lower = self._get_lower(2, *macro_vector)
        eq4_next_lower = self._get_lower(4, *macro_vector)
        eq5_next_lower = self._get_lower(5, *macro_vector)

        if eq3 == 1 and eq6 == 1:
            # 11 --> 21
            eq3eq6_next_lower = self._get_lower(3, *macro_vector)
        elif eq3 == 0 and eq6 == 1:
            # 01 --> 11
            eq3eq6_next_lower = self._get_lower(3, *macro_vector)
        elif eq3 == 1 and eq6 == 0:
            # 10 --> 11
            eq3eq6_next_lower = self._get_lower(6, *macro_vector)
        elif eq3 == 0 and eq6 == 0:
            # 00 --> 01
            # 00 --> 10
            eq3eq6_next_lower_left = self._get_lower(6, *macro_vector)
            eq3eq6_next_lower_right = self._get_lower(3, *macro_vector)
            if eq3eq6_next_lower_left > eq3eq6_next_lower_right:
                eq3eq6_next_lower = eq3eq6_next_lower_left
            else:
                eq3eq6_next_lower = eq3eq6_next_lower_right
        else:
            # 21 --> 32 (does not exist)
            eq3eq6_next_lower = float('nan')

        return eq1_next_lower, eq2_next_lower, eq3eq6_next_lower, eq4_next_lower, eq5_next_lower

    def severity_distances(self, macro_vector):
        def extract_value_metric(metric, max_vector: str):
            extracted = max_vector[max_vector.index(metric) + len(metric) + 1:]
            try:
                return extracted[:extracted.index("/")]
            except ValueError:
                return extracted

        def severity_distance(metric, levels, max_vector):
            return levels[self.metric(metric)] - levels[extract_value_metric(metric, max_vector)]

        eq1_maxes = MAX_COMPOSED["eq1"][macro_vector[0]]
        eq2_maxes = MAX_COMPOSED["eq2"][macro_vector[1]]
        eq3_eq6_maxes = MAX_COMPOSED["eq3"][macro_vector[2]][macro_vector[5]]
        eq4_maxes = MAX_COMPOSED["eq4"][macro_vector[3]]
        eq5_maxes = MAX_COMPOSED["eq5"][macro_vector[4]]

        max_vectors = []
        for eq1_max in eq1_maxes:
            for eq2_max in eq2_maxes:
                for eq3_eq6_max in eq3_eq6_maxes:
                    for eq4_max in eq4_maxes:
                        for eq5_max in eq5_maxes:
                            max_vectors.append("".join([eq1_max, eq2_max, eq3_eq6_max, eq4_max, eq5_max]))

        # Find the max vector to use i.e. one in the combination of all the highests
        # that is greater or equal (severity distance) than the to-be scored vector.
        for max_vector in max_vectors:
            severity_distance_AV = severity_distance("AV", {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}, max_vector)
            severity_distance_PR = severity_distance("PR", {"N": 0.0, "L": 0.1, "H": 0.2}, max_vector)
            severity_distance_UI = severity_distance("UI", {"N": 0.0, "P": 0.1, "A": 0.2}, max_vector)

            severity_distance_AC = severity_distance("AC", {'L': 0.0, 'H': 0.1}, max_vector)
            severity_distance_AT = severity_distance("AT", {'N': 0.0, 'P': 0.1}, max_vector)

            severity_distance_VC = severity_distance("VC", {'H': 0.0, 'L': 0.1, 'N': 0.2}, max_vector)
            severity_distance_VI = severity_distance("VI", {'H': 0.0, 'L': 0.1, 'N': 0.2}, max_vector)
            severity_distance_VA = severity_distance("VA", {'H': 0.0, 'L': 0.1, 'N': 0.2}, max_vector)

            severity_distance_SC = severity_distance("SC", {'H': 0.1, 'L': 0.2, 'N': 0.3}, max_vector)
            severity_distance_SI = severity_distance("SI", {'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3}, max_vector)
            severity_distance_SA = severity_distance("SA", {'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3}, max_vector)

            severity_distance_CR = severity_distance("CR", {'H': 0.0, 'M': 0.1, 'L': 0.2}, max_vector)
            severity_distance_IR = severity_distance("IR", {'H': 0.0, 'M': 0.1, 'L': 0.2}, max_vector)
            severity_distance_AR = severity_distance("AR", {'H': 0.0, 'M': 0.1, 'L': 0.2}, max_vector)

            if any([severity_distance_AV < 0, severity_distance_PR < 0, severity_distance_UI < 0,
                    severity_distance_AC < 0,
                    severity_distance_AT < 0, severity_distance_VC < 0, severity_distance_VI < 0,
                    severity_distance_VA < 0,
                    severity_distance_SC < 0, severity_distance_SI < 0, severity_distance_SA < 0,
                    severity_distance_CR < 0,
                    severity_distance_IR < 0, severity_distance_AR < 0]):
                # if any is less than zero this is not the right max
                continue
            break

        current_severity_distance_eq1 = severity_distance_AV + severity_distance_PR + severity_distance_UI
        current_severity_distance_eq2 = severity_distance_AC + severity_distance_AT
        current_severity_distance_eq3eq6 = severity_distance_VC + severity_distance_VI + severity_distance_VA + severity_distance_CR + severity_distance_IR + severity_distance_AR
        current_severity_distance_eq4 = severity_distance_SC + severity_distance_SI + severity_distance_SA
        current_severity_distance_eq5 = 0

        return current_severity_distance_eq1, current_severity_distance_eq2, current_severity_distance_eq3eq6, current_severity_distance_eq4, current_severity_distance_eq5

    def mean_distance(self, value, macro_vector, lower_scores, severity_distances):
        eq1_next_lower, eq2_next_lower, eq3eq6_next_lower, eq4_next_lower, eq5_next_lower = lower_scores

        step = 0.1

        # if the next lower macro score do not exist the result is Nan
        # Rename to maximal scoring difference (aka MSD)
        available_distance_eq1 = value - eq1_next_lower
        available_distance_eq2 = value - eq2_next_lower
        available_distance_eq3eq6 = value - eq3eq6_next_lower
        available_distance_eq4 = value - eq4_next_lower
        available_distance_eq5 = value - eq5_next_lower

        # some of them do not exist, we will find them by retrieving the score. If score null then do not exist
        n_existing_lower = 0

        normalized_severity_eq1 = 0
        normalized_severity_eq2 = 0
        normalized_severity_eq3eq6 = 0
        normalized_severity_eq4 = 0
        normalized_severity_eq5 = 0

        # multiply by step because distance is pure
        max_severity_eq1 = MAX_SEVERITY["eq1"][macro_vector[0]] * step
        max_severity_eq2 = MAX_SEVERITY["eq2"][macro_vector[1]] * step
        max_severity_eq3eq6 = MAX_SEVERITY["eq3eq6"][macro_vector[2]][macro_vector[5]] * step
        max_severity_eq4 = MAX_SEVERITY["eq4"][macro_vector[3]] * step

        #   c. The proportion of the distance is determined by dividing
        #      the severity distance of the to-be-scored vector by the depth
        #      of the MacroVector.
        #   d. The maximal scoring difference is multiplied by the proportion of
        #      distance.
        if not math.isnan(available_distance_eq1):
            n_existing_lower += 1
            percent_to_next_eq1_severity = (severity_distances[0]) / max_severity_eq1
            normalized_severity_eq1 = available_distance_eq1 * percent_to_next_eq1_severity

        if not math.isnan(available_distance_eq2):
            n_existing_lower += 1
            percent_to_next_eq2_severity = (severity_distances[1]) / max_severity_eq2
            normalized_severity_eq2 = available_distance_eq2 * percent_to_next_eq2_severity

        if not math.isnan(available_distance_eq3eq6):
            n_existing_lower += 1
            percent_to_next_eq3eq6_severity = (severity_distances[2]) / max_severity_eq3eq6
            normalized_severity_eq3eq6 = available_distance_eq3eq6 * percent_to_next_eq3eq6_severity

        if not math.isnan(available_distance_eq4):
            n_existing_lower += 1
            percent_to_next_eq4_severity = (severity_distances[3]) / max_severity_eq4
            normalized_severity_eq4 = available_distance_eq4 * percent_to_next_eq4_severity

        if not math.isnan(available_distance_eq5):
            # for eq5 is always 0 the percentage
            n_existing_lower += 1
            percent_to_next_eq5_severity = 0
            normalized_severity_eq5 = available_distance_eq5 * percent_to_next_eq5_severity

        # 2. The mean of the above computed proportional distances is computed.
        if n_existing_lower == 0:
            return 0

        # sometimes we need to go up but there is nothing there, or down but there is nothing there
        # so it's a change of 0.
        return sum([normalized_severity_eq1,
                    normalized_severity_eq2,
                    normalized_severity_eq3eq6,
                    normalized_severity_eq4,
                    normalized_severity_eq5]) / n_existing_lower

    def score(self):
        # If no impact at all, score is always 0
        if all([self.metric(metric) == "N" for metric in ["VC", "VI", "VA", "SC", "SI", "SA"]]):
            return 0.0

        macro_vector = self.macro_vector()

        value = self.lookup(*macro_vector)

        lower_scores = self.lower_scores(
            macro_vector)
        severity_distances = self.severity_distances(macro_vector)
        mean_distance = self.mean_distance(value, macro_vector, lower_scores, severity_distances)

        return round(max(0.0, min(value - mean_distance, 10.0)), 1)

    def scores(self):
        scores = OrderedDict()
        for i, group in enumerate(self.macro_vector()):
            scores[MACRO_VECTOR_NAMES[i]] = MACRO_VECTOR_VALUE_NAMES[group]
        return scores

    def clean_vector(self, output_prefix=True):
        """
        Returns vector without optional metrics marked as X and in preferred order.

        Args:
            output_prefix (bool): defines if CVSS vector should be printed with prefix

        Returns:
            (str): cleaned CVSS4 with metrics in correct order
        """
        vector = []
        for metric in METRICS_ABBREVIATIONS:
            if metric in self.original_metrics:
                value = self.original_metrics[metric]
                if value != "X":
                    vector.append("{0}:{1}".format(metric, value))
        if output_prefix:
            prefix = "CVSS:4.{0}/".format(self.minor_version)
        else:
            prefix = ""
        return prefix + "/".join(vector)

    def severity(self):
        """
        Returns severities based on scores.

        Returns:
            (tuple): Base Severity, Temporal Severity, Environmental Severity as strings
        """
        score = self.score()
        if score == D("0.0"):
            return "None"
        elif score <= D("3.9"):
            return "Low"
        elif score <= D("6.9"):
            return "Medium"
        elif score <= D("8.9"):
            return "High"
        return "Critical"

    def __eq__(self, o):
        if isinstance(o, CVSS4):
            return self.clean_vector().__eq__(o.clean_vector())
        return NotImplemented

    def __hash__(self):
        return hash(self.clean_vector())

    def as_json(self, sort=False, minimal=False):
        """
        Returns a dictionary formatted with attribute names and values defined by the official
        CVSS JSON schema:

        CVSS v4.0: https://www.first.org/cvss/cvss-v4.0.json?20231011

        Serialize a `cvss` instance to JSON with:

        json.dumps(cvss.as_json())

        Or get sorted JSON in an OrderedDict with:

        json.dumps(cvss.as_json(sort=True))

        Returns:
            (dict): JSON schema-compatible CVSS representation
        """

        # TODO: Implement

        def us(text):
            # If this is the (modified) attack vector description, convert it from "adjacent" to
            # "adjacent network" as defined by the schema.
            if text == "POC":
                return "PROOF_OF_CONCEPT"
            # Uppercase and convert to snake case
            return text.upper().replace("-", "_").replace(" ", "_")

        def add_metric_to_data(metric):
            k = METRICS_ABBREVIATIONS_JSON[metric]
            data[k] = us(self.get_value_description(metric))

        base_severity, temporal_severity, environmental_severity = self.severities()

        data = {
            "version": "4." + str(self.minor_version),
            "vectorString": self.vector,
        }

        for metric in METRICS_MANDATORY:
            add_metric_to_data(metric)
        data["baseScore"] = float(self.base_score)
        data["baseSeverity"] = us(base_severity)

        if not minimal or any(metric in self.original_metrics for metric in TEMPORAL_METRICS):
            for metric in TEMPORAL_METRICS:
                add_metric_to_data(metric)
            data["temporalScore"] = float(self.temporal_score)
            data["temporalSeverity"] = us(temporal_severity)

        if not minimal or any(metric in self.original_metrics for metric in ENVIRONMENTAL_METRICS):
            for metric in ENVIRONMENTAL_METRICS:
                add_metric_to_data(metric)
            data["environmentalScore"] = float(self.environmental_score)
            data["environmentalSeverity"] = us(environmental_severity)

        if sort:
            data = OrderedDict(sorted(data.items()))
        return data
