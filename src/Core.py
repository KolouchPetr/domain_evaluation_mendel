# Import basic modules and libraries
import json
import time
import re
import os
from typing import List
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 


# Import ML and data-processing libraries
import tensorflow as tf
import torch
import numpy as np
from array import array
import pickle
from dotenv import load_dotenv
from os import getenv



# Load custom modules
import Database
from Data_loader import Base_parser
import SSL_loader
import Lex
from Lex import Net
from Preprocessor import preprocess 



class clasifier:        
        def __init__(self) -> None:
            load_dotenv()
            self.mode = getenv("MODE")
            self.models = getenv("MODELS_FOLDER")

            self.hostname = None
            self.data = None
            self.loaded_data = False
            self.accuracy = 0
            

            if self.mode not in ['lexical', 'data', 'svm', 'mixed']:
                    print("[Error]: Invalid classification mode")
                    exit(1)

        
        def load_data(self, hostname: str):
                if not self.reset_data(hostname):
                        return self.data

                self.resolver_timeout = int(getenv("RESOLVER_TIMEOUT"))
                domain = Base_parser(hostname, self.resolver_timeout)

                domain.load_dns_data()
                domain.load_geo_info()
                domain.load_whois_data()
                domain.load_ssl_data()

                dns_data = domain.get_dns()
                geo_data = domain.get_geo_data()
                whois_data = domain.get_whois_data()
                ssl_data = domain.get_ssl_data()

                self.accuracy = np.around((Lex.is_empty(dns_data) + Lex.is_empty(geo_data) + Lex.is_empty(whois_data) + Lex.is_empty(ssl_data))/4, 3)

                in_data = {"name": hostname, "dns_data": dns_data, "geo_data": geo_data, "whois_data": whois_data, "ssl_data": ssl_data}
                
                self.data = Lex.process_data(in_data)

                self.loaded_data = True
        



        def get_lexical(self, hostname: str) -> float:
                self.lexical_model = tf.saved_model.load(self.models + '/domain_bigrams-furt-2020-11-07T11_09_21')
                parse = preprocess()
                bigrams = parse.preprocessing(hostname)

                iter = 43 - len(bigrams)
                for i in range(iter):
                        bigrams.append(0)
                if len(bigrams) > 43:
                        print("[Error]: Domain name to long, cant fit lexical model")
                        exit(1)  

                in_data = np.array([bigrams], dtype=np.float32)

                # Lexical models use inverse value
                return float(1 - self.lexical_model(in_data))


        # Prediction with support vector machines model
        def get_svm(self, hostname: str) -> float:
                self.load_data(hostname)
                svm_model = pickle.load(open(self.models + '/svm_model.smv', 'rb'))

                np_input = np.array([self.data], dtype=np.float32)
                prediction = svm_model.predict(np_input)

                return float(prediction)


        # Prediction with data-based model
        def get_data(self, hostname: str) -> float:
                self.load_data(hostname)
                data_model = torch.load(self.models + '/net_0.149_err.pt')

                torch_input = torch.tensor(self.data)
                prediction = data_model(torch_input)

                return float(prediction)

        # prediction with mixed model
        def get_mixed(self, hostname: str):
                self.load_data(hostname)

                # get predictions of all three models
                data = self.get_data(hostname)
                svm = self.get_svm(hostname)
                lexical = self.get_lexical(hostname)

                # more data we have, more accurate is data-based models
                prediction = data*self.accuracy + lexical*(1-self.accuracy)

                # svm acts like corrector
                if svm > 0.9:
                        if prediction > 0.5:
                                self.accuracy = (self.accuracy+1)/2
                                prediction = prediction*(2/3)+1/3
                        else:
                                prediction+=0.1
                                self.accuracy = (self.accuracy+0.5)/2
                else:
                        if prediction < 0.5:
                                self.accuracy = (self.accuracy+1)/2
                        else:
                                prediction-=0.1
                                self.accuracy = (self.accuracy+0.5)/2
                
                return prediction, self.accuracy

        def preload_data(self, data: list, hostname: str) -> None:
                self.hostname = hostname
                self.data = data
                self.loaded_data = True


        # Reset data loader
        def reset_data(self, hostname: str) -> bool:
                
                if self.hostname != hostname:
                        self.data = None
                        self.accuracy = None
                        self.loaded_data = False
                        self.hostname = hostname
                        return True
                else:
                        return False