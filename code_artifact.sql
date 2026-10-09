-- ==========================================
-- 1. ตั้งค่าพื้นฐานและลบข้อมูลเก่า (หากมี)
-- ==========================================
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;

-- ==========================================
-- 2. สร้างตาราง (Tables)
-- ==========================================
CREATE TABLE public.teachers (
    user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE
);

CREATE TABLE public.students (
    id text PRIMARY KEY CHECK (id ~ '^\d{11}$'), -- รหัสนักศึกษา 11 หลัก
    title text NOT NULL,
    first_name text NOT NULL,
    last_name text NOT NULL,
    section text NOT NULL,
    user_id uuid UNIQUE REFERENCES auth.users(id) ON DELETE SET NULL,
    photo_path text
);

CREATE TABLE public.attempts (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('pre', 'post')),
    score integer NOT NULL,
    answers jsonb NOT NULL,
    created_at timestamptz DEFAULT now(),
    UNIQUE (user_id, kind) -- ทำได้ครั้งเดียว
);

CREATE TABLE public.progress (
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    unit integer NOT NULL CHECK (unit BETWEEN 1 AND 5),
    done boolean DEFAULT false,
    updated_at timestamptz DEFAULT now(),
    PRIMARY KEY (user_id, unit)
);

CREATE TABLE public.submissions (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    unit integer NOT NULL,
    kind text NOT NULL CHECK (kind IN ('link', 'file')),
    url text,
    storage_path text,
    note text,
    score integer,
    teacher_comment text,
    created_at timestamptz DEFAULT now(),
    UNIQUE (user_id, unit)
);

CREATE TABLE public.materials (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    title text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('file', 'link', 'video')),
    url text,
    storage_path text,
    file_name text,
    created_at timestamptz DEFAULT now()
);

-- ==========================================
-- 3. ฟังก์ชันและ Trigger
-- ==========================================

-- 3.1 ฟังก์ชันเช็คสถานะผู้สอน (Security Definer)
CREATE OR REPLACE FUNCTION public.is_teacher()
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM teachers WHERE user_id = auth.uid());
END;
$$;

-- 3.2 Trigger ควบคุมการสมัครสมาชิกและผูกบัญชี
CREATE OR REPLACE FUNCTION public.handle_new_user_registration()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    student_id_val text;
BEGIN
    -- ถ้าอีเมลไม่ขึ้นต้นด้วยตัวเลข 11 หลัก ให้ข้ามไป (อาจเป็นผู้สอน)
    IF NEW.email !~ '^\d{11}@' THEN
        RETURN NEW;
    END IF;

    -- สกัดรหัสนักศึกษาจากอีเมล
    student_id_val := split_part(NEW.email, '@', 1);

    -- ตรวจสอบว่ามีชื่อในระบบและยังไม่ได้ผูกบัญชีหรือไม่
    IF NOT EXISTS (SELECT 1 FROM students WHERE id = student_id_val AND user_id IS NULL) THEN
        RAISE EXCEPTION 'รหัสนักศึกษาไม่มีในระบบ หรือบัญชีนี้ถูกใช้งานแล้ว';
    END IF;

    -- อัปเดตผูก user_id ทันที
    UPDATE students SET user_id = NEW.id WHERE id = student_id_val;
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created
    BEFORE INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user_registration();

-- 3.3 View สำหรับสรุปผล (Security Invoker = true)
CREATE VIEW public.results WITH (security_invoker = true) AS
SELECT 
    s.id AS student_id,
    s.title, s.first_name, s.last_name, s.section,
    s.photo_path,
    pre.score AS pre_score,
    post.score AS post_score,
    CASE 
        WHEN pre.score IS NULL OR post.score IS NULL THEN NULL
        WHEN pre.score = 10 THEN 0 -- ป้องกันการหารด้วยศูนย์ กรณีได้คะแนนเต็มก่อนเรียน
        ELSE ROUND(((post.score - pre.score)::numeric / (10 - pre.score)::numeric), 2)
    END AS normalized_gain,
    (SELECT COUNT(*) FROM progress p WHERE p.user_id = s.user_id AND p.done = true) AS units_completed
FROM public.students s
LEFT JOIN public.attempts pre ON s.user_id = pre.user_id AND pre.kind = 'pre'
LEFT JOIN public.attempts post ON s.user_id = post.user_id AND post.kind = 'post'
WHERE s.user_id IS NOT NULL;

-- ==========================================
-- 4. Row Level Security (RLS) Policies
-- ==========================================
ALTER TABLE public.teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.students ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.materials ENABLE ROW LEVEL SECURITY;

-- Teachers Table
CREATE POLICY "Teachers can view teachers" ON public.teachers FOR SELECT TO authenticated USING (is_teacher() OR user_id = auth.uid());

-- Students Table
CREATE POLICY "Users view own data or teachers view all" ON public.students FOR SELECT TO authenticated USING (user_id = auth.uid() OR is_teacher());
CREATE POLICY "Students can update own photo" ON public.students FOR UPDATE TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
-- ป้องกันนักเรียนแก้ไขฟิลด์อื่นผ่าน Column Privileges ไม่ได้ใน Supabase ตรงๆ จึงใช้วิธีอนุญาตเฉพาะ RLS และในแอปพลิเคชัน

-- Attempts Table
CREATE POLICY "View own attempts or teachers view all" ON public.attempts FOR SELECT TO authenticated USING (user_id = auth.uid() OR is_teacher());
CREATE POLICY "Students insert own attempt" ON public.attempts FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());

-- Progress Table
CREATE POLICY "View own progress or teachers view all" ON public.progress FOR SELECT TO authenticated USING (user_id = auth.uid() OR is_teacher());
CREATE POLICY "Students manage own progress" ON public.progress FOR ALL TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- Submissions Table
CREATE POLICY "View own submissions or teachers view all" ON public.submissions FOR SELECT TO authenticated USING (user_id = auth.uid() OR is_teacher());
CREATE POLICY "Students insert own submission" ON public.submissions FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());
-- ความปลอดภัย: นักเรียนอัปเดตงานตัวเองได้ แต่ห้ามแก้คะแนนและคอมเมนต์
CREATE POLICY "Students update own submission (no grading)" ON public.submissions FOR UPDATE TO authenticated USING (user_id = auth.uid() AND NOT is_teacher()) WITH CHECK (
    user_id = auth.uid() AND 
    score IS NOT DISTINCT FROM (SELECT score FROM public.submissions WHERE id = submissions.id) AND
    teacher_comment IS NOT DISTINCT FROM (SELECT teacher_comment FROM public.submissions WHERE id = submissions.id)
);
CREATE POLICY "Teachers can grade submissions" ON public.submissions FOR UPDATE TO authenticated USING (is_teacher()) WITH CHECK (is_teacher());

-- Materials Table
CREATE POLICY "Everyone views materials" ON public.materials FOR SELECT TO authenticated USING (true);
CREATE POLICY "Teachers manage materials" ON public.materials FOR ALL TO authenticated USING (is_teacher()) WITH CHECK (is_teacher());

-- ==========================================
-- 5. Storage Buckets & Policies
-- ==========================================
-- แทรกข้อมูล Buckets (ตั้งค่า limit ใน metadata)
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types) VALUES 
('photos', 'photos', false, 2097152, ARRAY['image/png', 'image/jpeg']), -- 2MB
('submissions', 'submissions', false, 20971520, ARRAY['image/png', 'image/jpeg', 'application/pdf', 'video/mp4']), -- 20MB
('materials', 'materials', false, 52428800, ARRAY['application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/pdf']); -- 50MB

-- Policies สำหรับ Storage
-- Photos
CREATE POLICY "View photos" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'photos' AND (is_teacher() OR (auth.uid())::text = (string_to_array(name, '/'))[1]));
CREATE POLICY "Manage own photos" ON storage.objects FOR ALL TO authenticated USING (bucket_id = 'photos' AND (auth.uid())::text = (string_to_array(name, '/'))[1]) WITH CHECK (bucket_id = 'photos' AND (auth.uid())::text = (string_to_array(name, '/'))[1]);

-- Submissions
CREATE POLICY "View submissions" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'submissions' AND (is_teacher() OR (auth.uid())::text = (string_to_array(name, '/'))[1]));
CREATE POLICY "Manage own submissions" ON storage.objects FOR ALL TO authenticated USING (bucket_id = 'submissions' AND (auth.uid())::text = (string_to_array(name, '/'))[1]) WITH CHECK (bucket_id = 'submissions' AND (auth.uid())::text = (string_to_array(name, '/'))[1]);

-- Materials
CREATE POLICY "View materials" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'materials');
CREATE POLICY "Teachers manage materials files" ON storage.objects FOR ALL TO authenticated USING (bucket_id = 'materials' AND is_teacher()) WITH CHECK (bucket_id = 'materials' AND is_teacher());

-- ==========================================
-- 6. ข้อมูลจำลอง (Mock Data)
-- ==========================================
-- ผู้สอนสามารถนำเข้าข้อมูลจริงผ่าน Table Editor (Import CSV) โดยมีคอลัมน์ id, title, first_name, last_name, section
INSERT INTO public.students (id, title, first_name, last_name, section) VALUES
('11111111111', 'นาย', 'สมชาย', 'เรียนดี', 'A'),
('22222222222', 'นางสาว', 'สมหญิง', 'ขยันยิ่ง', 'A'),
('33333333333', 'นาย', 'มานะ', 'อดทน', 'B'),
('44444444444', 'นางสาว', 'ปิติ', 'ยินดี', 'B'),
('55555555555', 'นาย', 'ชูใจ', 'รักเรียน', 'C'),
('66666666666', 'นางสาว', 'วีระ', 'กล้าหาญ', 'C');

-- ==========================================
-- 7. ตั้งค่าผู้สอน (ให้ผู้สอนแก้ไขอีเมลแล้ว Uncomment เพื่อรันเองภายหลัง)
-- ==========================================
-- INSERT INTO public.teachers (user_id) 
-- SELECT id FROM auth.users WHERE email = 'teacher@edu.fakeuni.ac.th';