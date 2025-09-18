# ssvc_converter.py
from enum import Enum

# --- Enums (Unchanged) ---
class ExploitationLevel(Enum):
    ACTIVE = "Active"
    POC = "PoC"
    NONE = "None"
class Automatable(Enum):
    YES = "Yes"
    NO = "No"
class TechnicalImpact(Enum):
    TOTAL = "Total"
    PARTIAL = "Partial"
class MissionImpact(Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
class SsvcAction(Enum):
    ACT = "Act"
    ATTEND = "Attend"
    TRACK_STAR = "Track*"
    TRACK = "Track"

class SsvcConverter:
    """
    A class to convert CVSS metrics, exploit maturity, and system context
    into a Stakeholder-Specific Vulnerability Categorization (SSVC) decision path and final action.
    """

    def get_exploitation_level(self, exploit_maturity: str) -> ExploitationLevel:
        # Fail Fast: Ensure input is a string
        if not isinstance(exploit_maturity, str):
            raise TypeError("exploit_maturity must be a string.")

        exploit_maturity = exploit_maturity.lower()
        active_states = {"active", "attacked", "high", "critical", "functional"}
        poc_states = {"poc", "proof-of-concept", "available"}

        if exploit_maturity in active_states: return ExploitationLevel.ACTIVE
        elif exploit_maturity in poc_states: return ExploitationLevel.POC
        else: return ExploitationLevel.NONE

    def is_automatable(self, attack_complexity: str, privileges_required: str, user_interaction: str) -> Automatable:
        # Fail Fast: Ensure all inputs are strings
        for arg_name, arg_val in locals().items():
            if arg_name != 'self' and not isinstance(arg_val, str):
                raise TypeError(f"{arg_name} must be a string.")

        is_auto = (attack_complexity.lower() == "l" and
                   privileges_required.lower() == "n" and
                   user_interaction.lower() == "n")
        return Automatable.YES if is_auto else Automatable.NO

    def get_technical_impact(self, confidentiality: str, integrity: str, availability: str) -> TechnicalImpact:
        # Fail Fast: Ensure all inputs are strings
        for arg_name, arg_val in locals().items():
            if arg_name != 'self' and not isinstance(arg_val, str):
                raise TypeError(f"{arg_name} must be a string.")

        # Fail Fast: Ensure values are valid CVSS metrics ('h', 'l', or 'n')
        valid_values = {'h', 'l', 'n'}
        for arg_name, arg_val in [('c', confidentiality), ('i', integrity), ('a', availability)]:
            if arg_val.lower() not in valid_values:
                raise ValueError(f"Invalid value for metric '{arg_name}': '{arg_val}'. Must be 'h', 'l', or 'n'.")

        is_total = (confidentiality.lower() == "h" and
                    integrity.lower() == "h" and
                    availability.lower() == "h")
        return TechnicalImpact.TOTAL if is_total else TechnicalImpact.PARTIAL

    def get_final_action(self, exploitation: ExploitationLevel, automatable: Automatable, tech_impact: TechnicalImpact, mission_impact: MissionImpact) -> SsvcAction:
        # This function already receives Enums, so it's inherently robust. No changes needed.
        if exploitation == ExploitationLevel.ACTIVE:
            if automatable == Automatable.YES: return SsvcAction.ACT
            else:
                if tech_impact == TechnicalImpact.PARTIAL: return SsvcAction.ATTEND
                else: return SsvcAction.ACT if mission_impact in [MissionImpact.HIGH, MissionImpact.MEDIUM] else SsvcAction.ATTEND
        elif exploitation == ExploitationLevel.POC:
            if automatable == Automatable.YES:
                if tech_impact == TechnicalImpact.PARTIAL: return SsvcAction.TRACK_STAR
                else: return SsvcAction.ATTEND if mission_impact in [MissionImpact.HIGH, MissionImpact.MEDIUM] else SsvcAction.TRACK_STAR
            else:
                if tech_impact == TechnicalImpact.PARTIAL: return SsvcAction.TRACK_STAR
                else: return SsvcAction.ATTEND if mission_impact == MissionImpact.HIGH else SsvcAction.TRACK_STAR
        else:
            if automatable == Automatable.YES:
                if tech_impact == TechnicalImpact.PARTIAL: return SsvcAction.TRACK
                else: return SsvcAction.ATTEND if mission_impact == MissionImpact.HIGH else SsvcAction.TRACK
            else:
                if tech_impact == TechnicalImpact.PARTIAL: return SsvcAction.TRACK
                else: return SsvcAction.TRACK_STAR if mission_impact == MissionImpact.HIGH else SsvcAction.TRACK

    def get_ssvc_decision_path(self, ac: str, pr: str, ui: str, c: str, i: str, a: str, exploit_maturity: str, system_context: str) -> dict:
        exploitation = self.get_exploitation_level(exploit_maturity)
        automatable = self.is_automatable(ac, pr, ui)
        tech_impact = self.get_technical_impact(c, i, a)

        # Fail Fast: Let the main script handle invalid system_context values
        mission_impact = MissionImpact(system_context.capitalize())

        final_action = self.get_final_action(exploitation, automatable, tech_impact, mission_impact)

        return {
            "path": {
                "Exploitation": exploitation.value,
                "Automatable": automatable.value,
                "Technical Impact": tech_impact.value,
                "Mission & Well-being": mission_impact.value
            },
            "action": final_action.value
        }