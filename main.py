from dataset.private import PrivateDataset
from classifier import byteiot, tmc, big_data, audi


def preprocess_private_dataset():
    private_dataset = PrivateDataset()
    private_dataset.run_tshark()
    private_dataset.get_entropy_feature()


if __name__ == '__main__':
    preprocess_dataset()
    byteiot_classifier = byteiot.ByteIoTClassifier()
    byteiot_classifier.get_archived_dataset('Private')
    byteiot_classifier.train_on_private_dataset()
    print('training phase completed')
    
    byteiot_classifier.test(PrivateDataset(), './byteiot-test.pkl')
    print('test phase completed')
