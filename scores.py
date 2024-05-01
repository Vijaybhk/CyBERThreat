from math import floor


class CVSScore:
    def __init__(self, metrics):
        self.metrics = metrics

    @staticmethod
    def round_up(inp_value):
        int_input = round(inp_value * 100000)
        if int_input % 10000 == 0:
            return int_input / 100000.0
        else:
            return (floor(int_input / 10000) + 1) / 10.0

    def get_av_score(self):
        metric = self.metrics["attack_vector"]
        if metric == 'network':
            return 0.85
        elif metric == 'adjacent_network':
            return 0.62
        elif metric == 'local':
            return 0.55
        elif metric == 'physical':
            return 0.20
        else:
            raise ValueError('Invalid metric value')

    def get_ac_score(self):
        metric = self.metrics["attack_complexity"]
        if metric == 'low':
            return 0.77
        elif metric == 'high':
            return 0.44
        else:
            raise ValueError('Invalid metric value')

    def get_pr_score(self):
        metric = self.metrics["privileges_required"]
        s = self.metrics["scope"]
        if metric == 'none':
            return 0.85
        elif metric == 'low':
            return 0.68 if s == 'changed' else 0.62
        elif metric == 'high':
            return 0.50 if s == 'changed' else 0.27
        else:
            raise ValueError('Invalid metric value')

    def get_ui_score(self):
        metric = self.metrics["user_interaction"]
        if metric == 'none':
            return 0.85
        elif metric == 'required':
            return 0.62
        else:
            raise ValueError('Invalid metric value')

    def get_c_score(self):
        metric = self.metrics["confidentiality"]
        if metric == 'high':
            return 0.56
        elif metric == 'low':
            return 0.22
        elif metric == 'none':
            return 0
        else:
            raise ValueError('Invalid metric value')

    def get_i_score(self):
        metric = self.metrics["integrity"]
        if metric == 'high':
            return 0.56
        elif metric == 'low':
            return 0.22
        elif metric == 'none':
            return 0
        else:
            raise ValueError('Invalid metric value')

    def get_a_score(self):
        metric = self.metrics["availability"]
        if metric == 'high':
            return 0.56
        elif metric == 'low':
            return 0.22
        elif metric == 'none':
            return 0
        else:
            raise ValueError('Invalid metric value')

    def calculate_iss(self):
        return 1 - (1 - self.get_c_score()) * (1 - self.get_i_score()) * (1 - self.get_a_score())

    def calculate_impact(self):
        iss = self.calculate_iss()
        s = self.metrics["scope"]
        if s == 'unchanged':
            return 6.42 * iss
        elif s == 'changed':
            return (7.52 * (iss - 0.029)) - (3.25 * (iss - 0.02) ** 15)
        else:
            raise ValueError('Invalid metric value')

    def calculate_exploitability(self):
        return 8.22 * self.get_av_score() * self.get_ac_score() * self.get_pr_score() * self.get_ui_score()

    def calculate_scores(self):
        impact = self.calculate_impact()
        exploitability = self.calculate_exploitability()
        s = self.metrics["scope"]
        if impact <= 0:
            base = 0
        else:
            if s == 'unchanged':
                base = min((impact + exploitability), 10)
            else:
                base = min(1.08 * (impact + exploitability), 10)
        return self.round_up(base), round(impact, 1), round(exploitability, 1)
