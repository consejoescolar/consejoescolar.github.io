-- Seguimiento privado de sugerencias sin cuentas de alumnos.
-- Ejecuta este archivo una sola vez en Supabase > SQL Editor, después de hacer copia de seguridad.
-- El código de consulta es un secreto bearer: solo quien lo tenga puede consultar esa sugerencia.

-- Las filas ya existentes no tendrán código, pero seguirán visibles en el panel de administradores.
ALTER TABLE public.suggestions
  ADD COLUMN IF NOT EXISTS tracking_token_hash text;

CREATE UNIQUE INDEX IF NOT EXISTS suggestions_tracking_token_hash_uidx
  ON public.suggestions (tracking_token_hash)
  WHERE tracking_token_hash IS NOT NULL;

-- Reemplaza la función de envío anterior. La aplicación genera el código aleatorio,
-- guarda el código en una cookie del navegador y solo envía a Supabase su SHA-256.
DROP FUNCTION IF EXISTS public.submit_suggestion(text, text, text);
DROP FUNCTION IF EXISTS public.submit_suggestion(text, text, text, text);

CREATE FUNCTION public.submit_suggestion(
  category_in text,
  title_in text,
  description_in text,
  name_in text,
  tracking_token_hash_in text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  clean_name text;
BEGIN
  IF category_in NOT IN (
    'Instalaciones',
    'Limpieza y mantenimiento',
    'Patio y zonas comunes',
    'Material escolar',
    'Actividades y eventos',
    'Convivencia',
    'Otras propuestas'
  ) THEN
    RAISE EXCEPTION 'Categoría no válida';
  END IF;

  IF char_length(trim(title_in)) NOT BETWEEN 3 AND 100 THEN
    RAISE EXCEPTION 'Título no válido';
  END IF;

  IF char_length(trim(description_in)) NOT BETWEEN 10 AND 2000 THEN
    RAISE EXCEPTION 'Descripción no válida';
  END IF;

  IF tracking_token_hash_in IS NULL
     OR tracking_token_hash_in !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'Código de consulta no válido';
  END IF;

  clean_name := NULLIF(trim(name_in), '');
  IF clean_name IS NOT NULL AND char_length(clean_name) > 80 THEN
    RAISE EXCEPTION 'Nombre demasiado largo';
  END IF;

  INSERT INTO public.suggestions (
    student_name, category, title, description, tracking_token_hash
  ) VALUES (
    clean_name, category_in, trim(title_in), trim(description_in), tracking_token_hash_in
  );
END;
$$;

REVOKE ALL ON FUNCTION public.submit_suggestion(text, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.submit_suggestion(text, text, text, text, text) TO anon, authenticated;

-- Esta función solo devuelve contenido público de la sugerencia asociada al código;
-- nunca expone student_name, private_notes ni otros registros.
CREATE OR REPLACE FUNCTION public.get_my_suggestion(tracking_token_hash_in text)
RETURNS TABLE (
  category text,
  title text,
  description text,
  status text,
  created_at timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT s.category, s.title, s.description, s.status, s.created_at
  FROM public.suggestions AS s
  WHERE s.tracking_token_hash = $1
  LIMIT 1;
$$;

REVOKE ALL ON FUNCTION public.get_my_suggestion(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_my_suggestion(text) TO anon, authenticated;
