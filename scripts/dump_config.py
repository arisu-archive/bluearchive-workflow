import argparse
import UnityPy


def main(path: str, output: str):
    env = UnityPy.load(path)
    for asset in env.assets:
        for obj in asset.objects.values():
            # check if the item is a TextAsset and the name is GameMainConfig
            if obj.type.name == "TextAsset":
                data = obj.read()
                if data.m_Name == "GameMainConfig":
                    with open(output, "wb") as f:
                        f.write(data.m_Script.encode("utf-8", "surrogateescape"))
                    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=str, required=True)
    parser.add_argument("-o", "--output", type=str, required=True)
    args = parser.parse_args()
    main(args.input, args.output)
