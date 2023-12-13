from abc import ABC


class Limits(ABC):
    def update(
        self,
        params: dict,
    ):
        common_keys = set(self.as_dict().keys()) & set(params.keys())
        new_limits = {k: params[k] for k in common_keys}
        self.__dict__.update(new_limits)

    def as_dict(self):
        return self.__dict__


class UnknownEnergyService(Exception):
    """
    it is raised when the Service Id is not recognized
    """
