import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
sns.set()

name = "T.Encap"
vinbero_single = [5.53648128, 4.1209036800000005, 3.47078656, 3.2007782400000004, 2.89275904, 2.807827329438202]
vinbero_multi = [70.02390528000001, 35.148267520000005, 17.53219072, 8.80541696, 4.40008704, 3.1556246723595502]
linux_single = [3.670016, 2.6633830400000003, 2.03423744, 1.8664652800000001,  1.53092096, 1.4524544862921347]
linux_multi = [23.320330239999997, 11.660165119999998, 5.84056832, 1.81665792, 1.4562099199999998, 1.0471621896629213]

left = np.arange(len(vinbero_single))
labels = [64, 128, 256, 512, 1024, 1424]
width = 0.3

plt.title(f"{name}/Payload pps (single flow)")
plt.ylabel("Mpps")
plt.xlabel("byte")

plt.bar(left, vinbero_single, color='r', width=width, align='center', label="vinbero")
plt.bar(left+width, linux_single, color='b', width=width, align='center', label="linux")

plt.xticks(left + width/2, labels)
plt.legend(bbox_to_anchor=(1, 1), loc='upper right', borderaxespad=0, fontsize=18)

plt.show()


left = np.arange(len(vinbero_multi))
plt.title(f"{name}/Payload pps (multi flow)")
plt.ylabel("Mpps")
plt.xlabel("byte")

plt.bar(left, vinbero_multi, color='r', width=width, align='center', label="vinbero")
plt.bar(left+width, linux_multi, color='b', width=width, align='center', label="linux")

plt.xticks(left + width/2, labels)
plt.legend(bbox_to_anchor=(1, 1), loc='upper right', borderaxespad=0, fontsize=18)
plt.show()
