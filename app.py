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
        with stylable_container(
                "red",
                css_styles="""
                    button {
                        background-color: #FF4B4B;
                        color: white;
                    }""",
        ):
            run_button = st.button("Run", key="run")

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

    def outputs(self, var: str, out_value: int | None = None):
        var_values = self.id_to_label[var]
        n_uniques = len(var_values)
        cols = st.columns([1]*(n_uniques+1))

        for i in range(n_uniques+1):
            with cols[i]:
                if out_value == i-1:
                    # Create buttons with st.button
                    with stylable_container(
                            "blue",
                            css_styles="""
                                button {
                                    background-color: #63C5DA;
                                    color: black;
                                    }
                                div[data-testid="column"] {
                                    width: fit-content !important;
                                    flex: unset;
                                    }
                                """,
                    ):
                        st.button(f"{var_values[out_value]}", disabled=True, key=f"{var}{i-1}")
                    # st.button(f":green[{var_values[out_value]}]", disabled=True)
                elif i == 0:
                    disp = var.replace("_", " ").upper()
                    st.markdown("""
                    <style>
                    .big-font {
                        font-size:22px !important;
                        color: #FFC300;
                        width: 300px;
                    }
                    </style>
                    <p class="big-font">""" + disp +
                                ":</p>", unsafe_allow_html=True)
                else:
                    st.button(f"{var_values[i-1]}", disabled=True, key=f"{var}{i-1}")

        return

    def app(self):
        text, run = self.styling()
        if run and text:
            st.write("")
            st.subheader(":red[Metrics]")
            metric_results = dict()
            for metric in ['attack_vector', 'attack_complexity', 'privileges_required', 'user_interaction', 'integrity']:
                result = self.get_prediction(hub_path=f"Vijaybhk/{metric.title()}-BERT", text=text)
                st.cache_resource.clear()
                self.outputs(var=metric, out_value=result)
                metric_results[metric] = result

            st.write("")
            st.subheader(":red[Scores]")
        return


if __name__ == "__main__":
    App = CyBERThreat()
    App.app()