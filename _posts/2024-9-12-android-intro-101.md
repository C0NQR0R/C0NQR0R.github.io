---
title: "أساسيات الاندرويد"
date: "2024-9-12"
layout: single
---

# مقدمة في اختراق تطبيقات الأندرويد - الجزء الاول 

 <div dir="auto">

بسم الله نبدأ! في السلسلة دي هنتكلم عن اساسيات اختراق تطبيقات الأندرويد، وإزاي نستغل الثغرات اللي ممكن نلاقيها في التطبيقات. هنطبق الكلام ده عملي على كذا سيناريو عشان نفهم الدنيا كويس، بس الأول لازم نعرف شوية معلومات أساسية عن **Android Architecture ** هناخد مثلاً، مقدمة نظرية عن الأندرويد أركيتكتشر، وإزاي النظام دا بيشتغل عشان نبقى فاهمين إيه اللي بيحصل لما بننزل أي APK بالتفصيل
 </div>

---

## مقدمة عن هيكلية الأندرويد - Android Architecture 

 <div dir="auto">
الفكرة كلها إن الأندرويد مبني على نظام لينكس، واللينكس شبيه بأي نظام تشغيل تاني، بيحتوي على مستخدمين. يعني زي الويندوز، ممكن يكون عندك يوسف وكريم، أو حتى يكون عندك حساب تاني له صلاحيات الأدمين. في اللينكس، نفس الشيء، عندك يوسف وكريم، وكمان روت اللي هو الحساب اللي معاه كل الصلاحيات.

لما بتنزل ملف APK على جهاز الأندرويد، النظام بيفكر فيه كأنه مستخدم جديد. يعني كل تطبيق زي البلاي ستور أو جوجل كروم، يعتبر كأنه شخص جديد على الجهاز. كل واحد فيهم بيكون له **يوزر ID** مختلف، يعنى بيتعامل مع النظام وكأنه مستخدم مستقل. حتى لو النظام الأساسي نفسه واحد، كل تطبيق بيكون له حساب مستخدم مستقل. ده بيخلينا نفكر في الأندرويد وكأنه بيدير كل تطبيق وكأنه مستخدم جديد، عشان يحافظ على الأمان ويقدر يتحكم في الصلاحيات بشكل منفصل لكل واحد فيهم.

الفكرة هي إن كل يوزر على جهاز الأندرويد ليه فولدراته الخاصة بيخزن فيها البيانات بتاعته. يعني كل يوزر مستقل عن التاني. لما بتنزل ملف APK مثلاً زي البلاي ستور أو كروم، كل واحد فيهم بيكون ليه فولدر خاص بيه على الجهاز يخزن فيه بياناته. ده بيساعد في عزل التطبيقات عن بعضها، ما بينفعش تطبيق فيسبوك يدخل ويشوف البيانات اللي تطبيق كروم مخزنها أو العكس. كل تطبيق محسوب كيوزر مختلف وله فولدراته المعزولة الخاصة، مش بيفوت على بعضها.

أما بالنسبة للـ **يوزر ID**، ده اللي بيكون مسؤول عن تشغيل البرنامج. يعني لما بتشغل أي برنامج، البرنامج ده (أو الـAPK) بيشتغل تحت اليوزر ده. زي لما تفتح برنامج معين على الكمبيوتر، كل برنامج يشتغل بشكل منفصل عن التاني. وبالتالي، كل تطبيق بيكون معزول عن التاني. كروم مش هيشوف بيانات فيسبوك وهكذا،  كل برنامج بيشتغل بمعزل عن التاني

دلوقتي موضوع الـ  **sandboxing** ممكن تحسه مرتبط شوية بال **virtualization** بس هما مش نفس الشئ
 **Sandboxing**: هو تقنية العزل التي توفر بيئة معزولة لكل تطبيق على جهاز الأندرويد أو نظام التشغيل لينكس بشكل عام. يهدف إلى منع التطبيقات من الوصول إلى بيانات التطبيقات الأخرى أو التأثير عليها. يشبه وضع كل تطبيق في صندوق خاص به، بحيث لا يستطيع تجاوز حدوده أو التأثير على التطبيقات الأخرى. حتى لو كان هناك خطأ في تطبيق ما، فهو لا يستطيع التأثير على النظام ككل أو التطبيقات الأخرى.
    
 **Virtualization**: يشير إلى تشغيل بيئات متعددة أو أنظمة تشغيل داخل نظام تشغيل واحد. في سياق الأندرويد، قد يتم تشغيل تطبيق داخل جهاز افتراضي بحيث يكون له نظام تشغيل صغير خاص به، ومعزول عن النظام الرئيسي. الـ **virtualization** يسمح بتشغيل عدة أنظمة أو تطبيقات بشكل مستقل، لكنه عادة ما يكون أكثر تعقيداً من الـ **sandboxing**.
    

بمعنى آخر، الـ **sandboxing** هو مجرد جزء من الـ **virtualization**. الـ **sandboxing** يركز على عزل التطبيقات، بينما الـ **virtualization** يمكن أن يشمل عزل الأنظمة بأكملها وتشغيلها بشكل مستقل داخل نظام التشغيل الرئيسي.


  </div>
  