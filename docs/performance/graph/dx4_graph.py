import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
sns.set()

name = "End.DX4"
vinbero_single = [3.9845887999999996, 1.9922943999999998, 2.87834112, 3.29252864, 3.5913728, 3.4723181878651688]
vinbero_multi = [3.9007027200000004, 1.9922943999999998, 2.9569843199999997, 3.34495744,3.6438016, 3.4402718202247193]
linux_single = [1.7496473600000002, 0.85302272, 1.30023424, 1.51781376,  1.62922496, 1.6607558759550562]
linux_multi = [1.69555968, 0.8663449599999999, 1.31072, 1.5151923200000001, 1.62791424, 1.659813335730337]

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
