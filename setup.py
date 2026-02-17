from setuptools import setup, find_packages

setup(
    name="Neural-Decompiler",
    version="1.0.0",
    description="A Neural Decompiler based on LongT5 and Angr",
    author="Frederik Graewert",
    packages=find_packages(),
    install_requires=[
        "transformers",
        "accelerate",
        "datasets",
        "sentencepiece",
        "torch",
        "deepspeed",
        "angr",
        "pyelftools",
        "capstone",
        "unicorn",
        "tqdm",
        "matplotlib",
        "numpy",
        "pandas",
        "seaborn",
        "requests"
    ],
    python_requires=">=3.10",
)