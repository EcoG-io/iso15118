from abc import ABC


class Limits(ABC):
    def update(
        self,
        params: dict,
    ):
        updated_params = {}
        for k, v in params.items():
            if type(v) is dict:
                updated_params.update({k: v["value"] * 10 ** v["exponent"]})
            elif type(v) in [int, float]:
                updated_params.update({k: v})

        self.__dict__.update(updated_params)

    def as_dict(self):
        return self.__dict__
