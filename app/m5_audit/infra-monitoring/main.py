from config import Config
from monitoring import MonitoringService


def main():

    config = Config()

    service = MonitoringService(config)

    service.run()


if __name__ == "__main__":
    main()