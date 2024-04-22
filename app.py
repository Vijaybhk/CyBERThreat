from __future__ import annotations

import numpy as np
import streamlit as st

from PIL import Image
from scores import CVSScore
from streamlit_extras.stylable_container import stylable_container
from transformers import BertTokenizer, BertForSequenceClassification


@st.cache_resource
def get_model(hub_path, model_str):
    tokenizer = BertTokenizer.from_pretrained(model_str, do_lower_case=True)
    model = BertForSequenceClassification.from_pretrained(hub_path, output_hidden_states=True)
    return tokenizer, model


def custom_markdown(display_md):
    st.markdown(
        """
        <style>
        .big-font {
        font-size:22px !important;
        color: #FFC300;
        width: 300px;
        }
        </style>
        """ +
        f"<p class='big-font'> {display_md} </p>",
        unsafe_allow_html=True)
    return


def custom_button(button_disp, button_key, button_color="#63C5DA", text_color="black", disabled=True):
    with stylable_container(
            f"{button_key}",
            css_styles="button {" +
            f"background-color: {button_color};" +
            f"color: {text_color};" +
            """ }
            div[data-testid='column'] {
                width: fit-content !important;
                flex: unset;
                }
            """,
    ):
        cust_button = st.button(f"{button_disp}", disabled=disabled, key=f"{button_key}")
    return cust_button


class CyBERThreat:
    id_to_label = {
        'attack_vector': {
            0: 'NETWORK',
            1: 'ADJACENT_NETWORK',
            2: 'LOCAL',
            3: 'PHYSICAL'
        },
        'attack_complexity': {
            0: 'LOW',
            1: 'HIGH',
        },
        'privileges_required': {
            0: 'NONE',
            1: 'LOW',
            2: 'HIGH',
        },
        'user_interaction': {
            0: 'NONE',
            1: 'REQUIRED',
        },
        'scope': {
            0: 'UNCHANGED',
            1: 'CHANGED',
        },
        'confidentiality': {
            0: 'NONE',
            1: 'LOW',
            2: 'HIGH',
        },
        'integrity': {
            0: 'NONE',
            1: 'LOW',
            2: 'HIGH',
        },
        'availability': {
            0: 'NONE',
            1: 'LOW',
            2: 'HIGH',
        },
    }

    def __init__(self, model_str='bert-base-uncased', max_length=512):
        self.model_str = model_str
        self.max_length = max_length
        return

    @staticmethod
    def styling():
        im = Image.open("cybersecurity.ico")
        st.set_page_config(layout="wide", page_title="CyBERThreat", page_icon=im)
        st.title(f":red[CyBERThreat]", anchor=False)
        st.divider()
        input_text = st.text_area("Enter vulnerability description here...")
        # run_button = st.button("Run")
        run_button = custom_button("Run", "run", "#FF4B4B", "white", False)

        return input_text, run_button

    def get_prediction(self, hub_path, text):
        tokenizer, model = get_model(hub_path=hub_path, model_str=self.model_str)
        encoded = tokenizer(
            [text],  # Sentence to encode.
            add_special_tokens=True,  # Add '[CLS]' and '[SEP]'
            max_length=self.max_length,  # Pad & truncate all sentences.
            padding='max_length',
            return_attention_mask=True,  # Construct attn. masks.
            return_tensors='pt',  # Return pytorch tensors.
            truncation=True,
        )
        out = model(**encoded)
        logits = out.logits
        pred = np.argmax(logits.detach().cpu().numpy(), axis=1)[0]

        return pred

    @staticmethod
    def outputs(var: str, out_value: int, var_uniques: list | dict, button_color="#63C5DA"):
        label = var_uniques[out_value]
        n_uniques = len(var_uniques)
        cols = st.columns([1]*(n_uniques+1))

        for i in range(n_uniques+1):
            with cols[i]:
                if out_value == i-1:
                    custom_button(button_disp=label, button_key=f"{var}{i - 1}", button_color=button_color)
                    # st.button(f":green[{var_values[out_value]}]", disabled=True)
                elif i == 0:
                    disp = var.replace("_", " ").upper()
                    custom_markdown(display_md=disp)
                else:
                    st.button(f"{var_uniques[i-1]}", disabled=True, key=f"{var}{i-1}")

        return label

    @staticmethod
    def display_score(score, value):
        col1, col2 = st.columns([1] * 2)
        with col1:
            custom_markdown(display_md=f"{score.upper()} SCORE")
        with col2:
            custom_button(button_disp=value, button_key=f"{score}")
        return

    def app(self):
        text, run = self.styling()
        if run and text:
            st.write("")
            st.subheader(":red[METRICS]")
            metric_results = dict()
            for metric in self.id_to_label.keys():
                result = self.get_prediction(hub_path=f"Vijaybhk/{metric.title()}-BERT", text=text)
                st.cache_resource.clear()
                var_values = self.id_to_label[metric]
                label = self.outputs(var=metric, out_value=result, var_uniques=var_values)
                metric_results[metric] = label.lower()

            st.write("")
            st.subheader(":red[SCORES]")
            b, i, e = CVSScore(metrics=metric_results).calculate_scores()
            for score in ["Impact", "Exploitability", "Base"]:
                if score == "Base":
                    self.display_score(score, b)
                elif score == "Impact":
                    self.display_score(score, i)
                elif score == "Exploitability":
                    self.display_score(score, e)

            sev_list = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if b == 0.0:
                severity = 0
                sev_color = "#50C878"
            elif 0.1 <= b <= 3.9:
                severity = 1
                sev_color = "#7CFC00"
            elif 4.0 <= b <= 6.9:
                severity = 2
                sev_color = "#FFBF00"
            elif 7 <= b <= 8.9:
                severity = 3
                sev_color = "#FF5F1F"
            else:
                severity = 4
                sev_color = "#C70039"

            self.outputs("severity", severity,sev_list, sev_color)

        return


if __name__ == "__main__":
    App = CyBERThreat()
    App.app()