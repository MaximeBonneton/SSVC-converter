# main.py
import json
import argparse
import pandas as pd
from ssvc_converter import SsvcConverter

# --- Data Loading Functions ---
def load_vulnerabilities_from_csv(filename: str) -> pd.DataFrame:
    """Loads vulnerabilities from a CSV file and returns a pandas DataFrame."""
    try:
        df = pd.read_csv(filename, delimiter=',')
        df.columns = df.columns.str.strip()
        return df
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        return pd.DataFrame()
    except Exception as e:
        print(f"Error while reading the CSV file: {e}")
        return pd.DataFrame()

# --- Main Function ---
def main():
    parser = argparse.ArgumentParser(description="Vulnerability prioritization tool using SSVC.")
    parser.add_argument("input_file", help="The input file (.csv) containing the vulnerabilities.")
    args = parser.parse_args()
    input_file = args.input_file

    if not input_file.lower().endswith('.csv'):
        print("Error: This version of the script is optimized for .csv files.")
        return

    print(f"--- Reading CSV file: {input_file} ---")
    dataframe = load_vulnerabilities_from_csv(input_file)

    if dataframe.empty:
        print("No data to process. Exiting program.")
        return

    print("--- Processing vulnerabilities ---")
    converter = SsvcConverter()

    # --- 1. Data Preparation (Input Metrics) ---
    exploit_mapping = {"internet": "active", "existant": "active", "proof of concept": "poc", "non prouvé": "none"}
    context_mapping = {"X": "medium", "XX": "high", "XXX": "high", "XXXX": "high"} # //////////// SHOULD BE UPDATED with the YOUR CONTEXT

    # --- THE FIX IS HERE (Part 1) ---
    # We remove .fillna('none') to stop assigning a default value.
    dataframe['exploit_maturity'] = dataframe['Nature Exploit'].str.lower().map(exploit_mapping)
    dataframe['system_context'] = dataframe['Criticité'].str.lower().map(context_mapping)

    def parse_cvss_vector(vector_string: str) -> dict:
        try:
            return {key.lower(): value.lower() for item in str(vector_string).split('/') for key, value in [item.split(':')]}
        except (ValueError, AttributeError):
            return {}

    cvss_metrics_df = dataframe['CVSS 3 Vecteur'].apply(parse_cvss_vector).apply(pd.Series)
    dataframe = pd.concat([dataframe, cvss_metrics_df], axis=1)

    # --- 2. SSVC Calculation with Error Handling per Row ---
    results_list = []
    for index, row in dataframe.iterrows():
        try:
            # Fail Fast: Check for missing CVSS data
            if row.get('ac') is None or pd.isna(row.get('ac')):
                raise ValueError("Données CVSS manquantes ou mal formatées")

            # --- THE FIX IS HERE (Part 2) ---
            # Fail Fast: Check for unrecognized 'Nature Exploit'
            if pd.isna(row.get('exploit_maturity')):
                raise ValueError(f"Nature Exploit non reconnue: '{row['Nature Exploit']}'")

            # Fail Fast: Check for unrecognized 'Criticité'
            if pd.isna(row.get('system_context')):
                raise ValueError(f"Criticité non reconnue: '{row['Criticité']}'")

            decision = converter.get_ssvc_decision_path(
                ac=row["ac"], pr=row["pr"], ui=row["ui"], c=row["c"], i=row["i"], a=row["a"],
                exploit_maturity=row["exploit_maturity"], system_context=row["system_context"]
            )

            flat_results = {
                'SSVC Exploitation': decision['path']['Exploitation'],
                'SSVC Automatable': decision['path']['Automatable'],
                'SSVC Technical Impact': decision['path']['Technical Impact'],
                'SSVC Action': decision['action']
            }
            results_list.append(flat_results)

        # Catch any error raised for this specific row
        except (ValueError, TypeError, KeyError) as e:
            results_list.append({
                'SSVC Exploitation': 'Erreur', 'SSVC Automatable': 'Erreur',
                'SSVC Technical Impact': 'Erreur', 'SSVC Action': f'Erreur de traitement: {e}'
            })

    # --- 3. Adding All Result Columns ---
    results_df = pd.DataFrame(results_list, index=dataframe.index)
    final_df = pd.concat([dataframe, results_df], axis=1)

    # --- 4. Renaming Columns for Readability ---
    rename_mapping = {
        'av': "Vecteur d'Attaque (AV)", 'ac': "Complexité d'Attaque (AC)", 'pr': "Privilèges Requis (PR)",
        'ui': "Interaction Utilisateur (UI)", 's': "Portée (S)", 'c': "Impact Confidentialité (C)",
        'i': "Impact Intégrité (I)", 'a': "Impact Disponibilité (A)",
        'exploit_maturity': "Maturité Exploit (Standard)", 'system_context': "Contexte Système (Standard)",
        'SSVC Exploitation': "SSVC - Niveau d'Exploitation", 'SSVC Automatable': "SSVC - Est Automatisable",
        'SSVC Technical Impact': "SSVC - Impact Technique", 'SSVC Action': "SSVC - Action Finale"
    }
    final_df = final_df.rename(columns=rename_mapping)

    # --- 5. Translating Metric Values ---
    impact_map = {'n': 'Aucun', 'l': 'Faible', 'h': 'Élevé'}
    value_translation_map = {
        "Vecteur d'Attaque (AV)": {'n': 'Réseau', 'a': 'Adjacent', 'l': 'Local', 'p': 'Physique'},
        "Complexité d'Attaque (AC)": {'l': 'Faible', 'h': 'Élevée'},
        "Privilèges Requis (PR)": {'n': 'Aucun', 'l': 'Faibles', 'h': 'Élevés'},
        "Interaction Utilisateur (UI)": {'n': 'Aucune', 'r': 'Requise'},
        "Portée (S)": {'u': 'Inchangée', 'c': 'Changée'},
        "Impact Confidentialité (C)": impact_map, "Impact Intégrité (I)": impact_map, "Impact Disponibilité (A)": impact_map,
    }
    final_df = final_df.replace(value_translation_map)

    # --- 6. Saving the Output ---
    output_file = input_file.replace('.csv', '_ssvc_rapport_final.csv')
    try:
        final_df.to_csv(output_file, index=False, sep=';', encoding='utf-8-sig')
        print(f"\n✅ Success! The final report has been saved to: {output_file}")
    except Exception as e:
        print(f"\n❌ Error while saving the file: {e}")

if __name__ == "__main__":
    main()