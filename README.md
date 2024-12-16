
الـ **Sysmon** دي ممكن تستخدمها في حاجات زي **suspicious behavior detection** و **threat hunting**.

بالبلدي، هي عينك اللي جوا الـ **Windows**، وبالطبع هي شغالة على **Linux** كمان.

لكن أهم حاجة إنك تحدد الـ **scope** بتاعك من خلال الـ **configuration file** اللي انت هتعمله.

---

### 1- **Sysmon Installation:**

ممكن تنزل الـ **Sysmon** من الموقع الرسمي هنا:  
[تحميل Sysmon](https://download.sysinternals.com/files/Sysmon.zip)

- فك الضغط عن الملف.
- افتح **cmd** في المسار اللي فكيت فيه الضغط.
- اكتب الأمر التالي لتثبيت الـ **service** والـ **driver**:
  ```
  sysmon -accepteula -i
  ```
  - **-i** علشان تثبت الـ **service** والـ **driver**.
  - **--accepteula** علشان تقبل التراخيص.

وإذا كنت معاك **configuration file** جاهز، ممكن تضيف المسار بتاعه، والملف ده هيكون بصيغة **XML** زي الملف ده:  
[مثال على Configuration File](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml)

لكن الأحسن إنك تستخدم **configuration file** مخصص ليك، لأن الـ **default** مش هيفيدك قوي.

أما لو الـ **Sysmon** متثبت بالفعل، وعايز تغير الـ **configuration file**، استخدم الأمر ده:
```
sysmon -c new_cf.xml
```
حيث إن **new_cf.xml** هو اسم الـ **configuration file** الجديد اللي انت عامل له.

---

### 2- **Configuration File:**

ركز معايا هنا جدًا، لأن دي النقطة اللي هتفرق معاك كتير.  
من خلال الموقع الرسمي، تقدر تلاقي تفاصيل عن كيفية استخدام **event filtering entries**:

[المزيد عن Event Filtering في Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-filtering-entries)

الملف ده هيكون هو الـ **template** اللي هتكتب فيه كل الـ **configurations** الخاصة بيك.
```
<Sysmon schemaversion="4.30">
    <EventFiltering>
		و هنا بنكتب ال configurations بتاعتنا
    </EventFiltering>
</Sysmon>
```
طيب لو انا عايز اراقب الاتصالات اللي هتجيلي على ال port 4444 سهلة 
```
<Sysmon schemaversion="4.30">
    <EventFiltering>
		<RuleGroup name="port4444Connetion" groupRelation="or">
		    <NetworkConnect onmatch="include">
			<DestinationPort condition="is">4444</DestinationPort>
	    	    </NetworkConnect>
                 </RuleGroup>
    </EventFiltering>
</Sysmon>
```
الكلام دا معناه ان اي اتصال جايلك على ال port 4444 هتعملي بيه log 

طيب لو انا عايز لو ال port 22 كمان و كمان لو تطبيق معين بيعمل اتصال ب حد 
```
<RuleGroup name="" groupRelation="or">
            <NetworkConnect onmatch="include">
                <Image condition="is">C:\Windows\System32\cmd.exe</Image>
                <User condition="is">Administrator</User>
            </NetworkConnect>
	    <NetworkConnect onmatch="include">
		<DestinationPort condition="is">4444</DestinationPort>
	    </NetworkConnect>
	    <NetworkConnect onmatch="include">
		<DestinationPort condition="is">8000</DestinationPort>
	    </NetworkConnect>
	    <NetworkConnect onmatch="include">
		<DestinationPort condition="is">22</DestinationPort>
	    </NetworkConnect>
        </RuleGroup>
```
طيب لو حد فتح app ك admin
```
<RuleGroup name="AdminCmd" groupRelation="or">
            <ProcessCreate onmatch="include">
                <Image condition="is">C:\Windows\System32\cmd.exe</Image>
                <User condition="is">Administrator</User>
            </ProcessCreate>
        </RuleGroup>
```
طيب لو فتح app مش ك  admin
```
<RuleGroup name="NonAdminCmd" groupRelation="or">
            <ProcessCreate onmatch="include">
                <Image condition="is">C:\Windows\System32\cmd.exe</Image>
                <User condition="is not">Administrator</User>
            </ProcessCreate>
        </RuleGroup>
```
طيب في العموم 
```
<RuleGroup name="notepad_opened" groupRelation="or">
            <ProcessCreate onmatch="include">
                <Image condition="is">C:\Windows\System32\notepad.exe</Image>
            </ProcessCreate>
        </RuleGroup>
```
طيب عايز اركز على directory معين واشوف حصل حذف واضافة و تعديل
```
<RuleGroup name="Monitor_sasa_FileChanges" groupRelation="or">
            <FileDelete onmatch="include">
                <User condition="contains any">NETWORK SERVICE; LOCAL SERVICE</User>
                <Rule name="Profile Deletion" groupRelation="and">
                    <TargetFilename condition="contains any">E:\UNINSTALL_TOOLS\sysmon_test</TargetFilename>
                </Rule>
            </FileDelete>
            <FileCreate onmatch="include">
                <TargetFilename condition="contains any">E:\UNINSTALL_TOOLS\sysmon_test</TargetFilename>
            </FileCreate>
            <FileCreateStreamHash onmatch="include">
                <TargetFilename condition="contains any">E:\UNINSTALL_TOOLS\sysmon_test</TargetFilename>
            </FileCreateStreamHash>
        </RuleGroup>
```
ركز في ال groupRelation , condition, onmatch
---

**ملاحظة:** تأكد إنك بتحدد ال **events** اللي هتراقبها بناءً على حاجتك. زي ما شوفنا، فيه أمثلة هتفيدك في مراقبة **file** و **process** والأشياء المهمة التانية.

---

**دا مش اخر ملخص لل tool ولسه هعدل عليه بس دا بداية بسيطة ارجوا انك تاخد لفة ف الموقع الرسمي و تكتب configurations ب ايدك.**

