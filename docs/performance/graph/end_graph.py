import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
sns.set()

formatimage = "pdf"
name = "End"
vinbero_single = [7.73849088, 3.8587596800000004, 3.48127232, 3.4865152000000004, 3.49175808, 3.483628670561798]
vinbero_multi = [7.61266176, 3.54418688, 3.4340864, 3.42884352, 3.43801856, 3.4327314984269663]
linux_single = [3.64904448, 1.85597952, 1.82976512, 1.8664652800000001, 1.87826176, 1.8322981968539327]
linux_multi = [3.71195904, 1.8874368000000001, 1.8507366399999998, 1.81665792, 1.85991168, 1.8134473923595504]

left = np.arange(len(vinbero_single))
labels = [64, 128, 256, 512, 1024, 1424]
width = 0.3

plt.title(f"{name}/Payload pps (single flow)")
plt.ylabel("Mpps")
plt.xlabel("byte")

plt.bar(left, vinbero_single, color='r', width=width, align='center', label="vinbero")
plt.bar(left+width, linux_single, color='b', width=width, align='center', label="linux")

plt.xticks(left + width/2, labels)
plt.legend(loc="best")
plt.savefig(f"./images/end_single_flow.{formatimage}")


left = np.arange(len(vinbero_multi))
plt.title(f"{name}/Payload pps (multi flow)")
plt.ylabel("Mpps")
plt.xlabel("byte")

plt.bar(left, vinbero_multi, color='r', width=width, align='center', label="vinbero")
plt.bar(left+width, linux_multi, color='b', width=width, align='center', label="linux")

plt.xticks(left + width/2, labels)
plt.savefig(f"./images/end_multi_flow.{formatimage}")
