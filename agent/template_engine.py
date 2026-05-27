from agent import compat
from agent.tools import sampling_tools, similarity_tools

compat.ensure_parser_path()

import llama_parser


class AgentTemplateEngine(llama_parser.LogParser):
    def cosine_similarity_distance(self, x, y):
        return similarity_tools.cosine_distance(x, y)

    def jaccard_distance(self, x, y):
        return similarity_tools.jaccard_distance(x, y)

    def min_distance(self, c_set, t_set):
        return similarity_tools.minimum_distances(c_set, t_set, self.similarity)

    def adaptive_random_sampling(
        self, logs, k, max_logs=200, similarity_flag=False, dic=False
    ):
        return sampling_tools.select_representative_logs(
            logs=logs,
            sample_size=k,
            metric=self.similarity,
            max_logs=max_logs,
            nearest=similarity_flag,
            records=dic,
        )

