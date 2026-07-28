import pandas as pd
from pathlib import Path
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
import os
from matplotlib import pyplot as plt
from elftools.elf.elffile import ELFFile

DIR = 'Signatures'
TEST_ID = "test_2"
BASE_PATH = Path(__file__).resolve().parent


def get_files(curdir='.') -> list:
    """Produce list with name of files, containing signatures of all architectures
    :curdir -> relative path, where locates 'Signatures' folder
    :return -> list with filenames
    """
    try:
        for root, dirs, files in os.walk(curdir):
            for file in files:
                if not file.endswith('.sig'):
                    files.remove(file)
            return files

    except (Exception, IOError) as e:
        print(e)
        raise Exception


def make_pd(files: list):
    """Create gold dataframe with example of Velocity Bytes Characteristic.
    :files -> list wit filenames, containing signatures for various architectures
    :return -> DataFrame
    """
    result_df = pd.DataFrame()
    for file in files:
        cur_df = pd.read_csv(DIR + '\\' + file, delimiter='\t', header=None)
        cur_df = cur_df.drop([cur_df.columns[-1], cur_df.columns[0]], axis=1)
        cur_df = cur_df.T
        cur_df['class'] = file.split('.')[0]

        ############## Uncomment for creating Bars with VBC for golden files###########################
        # fig = plt.figure()
        #
        # plt.bar(cur_df.columns[:len(cur_df.columns) - 1], cur_df.drop(['class'], axis=1).values[0])
        # plt.xlabel("Byte")
        # plt.ylabel("P")
        # plt.yticks([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8])
        # plt.savefig(f'{file.split(".")[0]}.png')
        # fig.clear()
        ###############################################################################################

        result_df = pd.concat([result_df, cur_df], ignore_index=True)
        print()

    return result_df


def make_dir_orig_files(name):
    """Make dirs assotiated with research files
    :name -> name of file. Create directory in 'results' folder.
    :return -> None
    """
    folder = BASE_PATH / 'experiment' / 'results' / name.split('_')[1]
    if not os.path.exists(folder):
        os.makedirs(folder)


def make_dir_results(path=BASE_PATH / 'experiment' / 'elf_arch_upxed'):
    """Make dirs assotiated with researched files
    :path -> specify directory that contains packed files.
    :return -> None
    """
    for root, dirs, files in os.walk(path):
        for file in files:
            make_dir_orig_files(file)


def draw_bar(dataframe, save_name='test2.png'):
    """Create bar containing Velocity Bytes Characteristic.
    :dataframe -> contains velocity of bytes investigated file
    :return -> None
    """
    fig = plt.figure()
    plt.bar(dataframe.columns, dataframe.values[0])
    plt.xlabel("Byte")
    plt.ylabel("P")
    plt.yticks([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    plt.savefig(save_name)


def parse_bin(name='test_2', path=BASE_PATH/'Tests', simple=True):
    """Parse bin with aim to create Velocity Bytes Characteristic, produce dataframe
    :name -> researched file
    :path -> relative path to folder, contains researched file
    :simple -> specify if the file is packed. If True the file is not packed, otherwise you have to specify
    bytes with assembler instructions
    :return DataFrame() -> df contains Velocity Bytes Characteristic"""
    data = list()
    size = None

    if simple:
        f_path = path / name
        with open(f_path, 'rb') as f:
            elffile = ELFFile(f)
            # 0x619fb0
            print(f'Binary machine header: {elffile.header["e_machine"]}')
            if elffile.has_section('.text'):
                for section in elffile.iter_sections():
                    if section.name == '.text':
                        data = section.data()
                        size = section.data_size
            else:
                data = elffile.get_segment(1)
                seg_data = data.data()

    else:
        with open(path / name, 'rb') as f:
            full_data = f.read()

            # Specify bytes ranges, that have asm code here:
            data = full_data[0x77eb8:0x7804c] + full_data[0x78100:0x781d8] + full_data[0x78258:0x78290]
            size = len(data)

    lst = [data.count(x) for x in range(256)]
    lst2 = [x / size for x in lst]
    maximum = max(lst2)
    norm = [x / maximum for x in lst2]

    return pd.DataFrame(norm).T


if __name__ == '__main__':
    #  make dirs for results
    # make_dir_results()

    curfile = 'test_Armv7a'
    folder = 'elf_arch'
    curpath_to_target = BASE_PATH / 'experiment' / folder

    # if filename has 2 '_' add -> f'{curfile.split("_")[2]}

    curpath_to_save = BASE_PATH / 'experiment' / 'results' / f'{curfile.split("_")[1]}'
    anon_file = parse_bin(name=curfile, path=curpath_to_target)
    draw_bar(anon_file, save_name=str(curfile))

    bin_files = get_files(DIR)
    bin_classes = [name.split('.')[0] for name in bin_files]
    gold_df = make_pd(bin_files)
    # encode labels
    lb = LabelEncoder()
    gold_df['labels'] = lb.fit_transform(gold_df['class'])
    gold_df = gold_df.drop(['class'], axis=1)

    # Start making KNN clf
    x_train = gold_df.drop(['labels'], axis=1)
    y_train = gold_df['labels']

    # KNN clf
    kn_clf = KNeighborsClassifier(n_neighbors=3)
    kn_clf.fit(x_train, y_train)

    with open(f'{curpath_to_save}\\res.txt', 'w') as f:

        y_predicts = kn_clf.predict(anon_file)
        print(f'Knn classifier: {lb.inverse_transform(y_predicts)}')
        print(f'Knn probabilities: {kn_clf.predict_proba(anon_file)}')
        print('\n')

        print(f'Knn classifier: {lb.inverse_transform(y_predicts)}', file=f)
        print(f'Knn probabilities: {kn_clf.predict_proba(anon_file)}', file=f)
        print('\n', file=f)

        # Logistic regression
        lg_clf = LogisticRegression(random_state=25)
        lg_clf.fit(x_train, y_train)
        y_predicts2 = lg_clf.predict(anon_file)

        print(f'Logistic classifier decision: {lb.inverse_transform(y_predicts2)}')
        print(f'Logistic probabilities: {lg_clf.predict_proba(anon_file)}')

        print(f'Logistic classifier decision: {lb.inverse_transform(y_predicts2)}', file=f)
        print(f'Logistic probabilities: {lg_clf.predict_proba(anon_file)}', file=f)

        # Random forest classifier
        fr_clf = RandomForestClassifier(random_state=25)
        fr_clf.fit(x_train, y_train)
        y_predicts3 = fr_clf.predict(anon_file)

        print(f'Random forest decision: {lb.inverse_transform(y_predicts3)}')
        print(f'Random probabilities: {fr_clf.predict_proba(anon_file)}')

        print(f'Random forest decision: {lb.inverse_transform(y_predicts3)}', file=f)
        print(f'Random probabilities: {fr_clf.predict_proba(anon_file)}', file=f)
